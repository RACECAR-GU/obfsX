package riverrun

import (
  "net"
  "crypto/aes"
  "crypto/cipher"
  "math/rand"
  "gitlab.com/yawning/obfs4.git/common/drbg"
  "gitlab.com/yawning/obfs4.git/common/log"
  "gitlab.com/yawning/obfs4.git/common/ctstretch"
  f "gitlab.com/yawning/obfs4.git/common/framing"
)

// Implements the net.Conn interface
type RiverrunConn struct {
  // Embeds a net.Conn and inherits its members.
  net.Conn

  bias float64

  Encoder *riverrunEncoder
  Decoder *riverrunDecoder
}

func NewRiverrunConn(conn net.Conn, isServer bool, seed *drbg.Seed) (*RiverrunConn, error) {
  // FIXME: Bias was arbitrarily selected
  bias := float64(0.55)

  xdrbg, _ := drbg.NewHashDrbg(seed) // TODO: Add error catch?
	rng := rand.New(xdrbg)
  key := make([]byte, 16)
	rng.Read(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

  iv := make([]byte, block.BlockSize())
	rng.Read(iv)

  stream := cipher.NewCTR(block, iv)

  // FIXME: Input and output block bits are randomly selected from valid options,
  //        there may be a more optimal selection methedology/initial subset
  compressedBlockBits := uint64((rng.Intn(2)+1) * 8)

  var expandedBlockBits uint64
  var expandedBlockBits8 uint64
	if compressedBlockBits == 8 {
		expandedBlockBits = uint64((rng.Intn(7)+2) * 8)
    expandedBlockBits8 = compressedBlockBits
	} else {
		expandedBlockBits = uint64((rng.Intn(3)+2) * 16)
    expandedBlockBits8 = compressedBlockBits / 2
	}

  table8, err := ctstretch.SampleBiasedStrings(expandedBlockBits8, 256, bias, stream)
  if err != nil {
		return nil, err
	}
  table16, err := ctstretch.SampleBiasedStrings(expandedBlockBits, 65536, bias, stream)
  if err != nil {
		return nil, err
	}

  var readStream, writeStream cipher.Stream
  readKey := make([]byte, drbg.SeedLength)
  writeKey := make([]byte, drbg.SeedLength)
  // XXX: The only distinction between the read and write streams is the iv... is this secure?
  if isServer {
    readStream = stream
    rng.Read(iv)
    writeStream = cipher.NewCTR(block, iv)
    rng.Read(readKey)
    rng.Read(writeKey)
  } else {
    writeStream = stream
    rng.Read(iv)
    readStream = cipher.NewCTR(block, iv)
    rng.Read(writeKey)
    rng.Read(readKey)
  }
  rr := new(RiverrunConn)
  rr.Conn = conn
  rr.bias = bias
  // Encoder
  rr.Encoder = newRiverrunEncoder(writeKey)
  rr.Encoder.writeStream = writeStream
  rr.Encoder.table8 = table8
  rr.Encoder.table16 = table16
  rr.Encoder.compressedBlockBits = compressedBlockBits
  rr.Encoder.expandedBlockBits = expandedBlockBits
  // Decoder
  rr.Decoder = newRiverrunDecoder(readKey)
  rr.Decoder.readStream = readStream
  rr.Decoder.revTable8 = ctstretch.InvertTable(table8)
  rr.Decoder.revTable16 = ctstretch.InvertTable(table16)
  rr.Decoder.compressedBlockBits = compressedBlockBits
  rr.Decoder.expandedBlockBits = expandedBlockBits
  return rr, nil
}

type riverrunEncoder struct {
  f.BaseEncoder

  writeStream cipher.Stream

  table8 []uint64
  table16 []uint64

  compressedBlockBits uint64
  expandedBlockBits uint64
}
func (encoder *riverrunEncoder) payloadOverhead(payloadLen int) int {
  return int(ctstretch.ExpandedNBytes(uint64(payloadLen), encoder.compressedBlockBits, encoder.expandedBlockBits)) - payloadLen
}
func (encoder *riverrunEncoder) encode(frame, payload []byte) (n int, err error) {
  expandedNBytes := int(ctstretch.ExpandedNBytes(uint64(len(payload)), encoder.compressedBlockBits, encoder.expandedBlockBits))
  err = ctstretch.ExpandBytes(payload[:], frame, encoder.compressedBlockBits, encoder.expandedBlockBits, encoder.table16, encoder.table8, encoder.writeStream)
  if err != nil {
    return 0, err
  }
  return expandedNBytes, err
}
func (encoder *riverrunEncoder) chopPayload(pktType uint8, payload []byte) []byte {
  return nil // TODO: Implement
}

type riverrunDecoder struct {
  Drbg *drbg.HashDrbg // TODO: Replace with BaseDecoder

  readStream cipher.Stream

  revTable8 map[uint64]uint64
  revTable16 map[uint64]uint64

  compressedBlockBits uint64
  expandedBlockBits uint64
}

func newRiverrunDecoder(key []byte) *riverrunDecoder {
  decoder := new(riverrunDecoder)
  decoder.Drbg = f.GenDrbg(key[:])
  return decoder
}

func newRiverrunEncoder(key []byte) *riverrunEncoder {
  encoder := new(riverrunEncoder)

	encoder.Drbg = f.GenDrbg(key[:])

  encoder.Encode = encoder.encode

  encoder.MaxPacketPayloadLength = 100000000000 // f.MaximumSegmentLength -  // TODO: Remember to fix this later

  encoder.PayloadOverhead = encoder.payloadOverhead

  encoder.ChopPayload = encoder.chopPayload

  return encoder
}

func (rr *RiverrunConn) Write(b []byte) (int, error) {
  expandedNBytes := ctstretch.ExpandedNBytes(uint64(len(b)), rr.Encoder.compressedBlockBits, rr.Encoder.expandedBlockBits)

  frame := make([]byte, expandedNBytes)
  n, err := rr.Encoder.encode(frame, b)
  if err != nil {
    return 0, nil
  }
  _, err = rr.Conn.Write(frame)
  log.Debugf("Riverrun: %d expanded to %d ->", len(b), n)
  return n, err
}

func (rr *RiverrunConn) Read(b []byte) (int, error) {
  n, err := rr.Conn.Read(b)
  if err != nil {
    return n, err
  }
  compressedNBytes := ctstretch.CompressedNBytes(uint64(n), rr.Decoder.expandedBlockBits, rr.Decoder.compressedBlockBits)
  compressed := make([]byte, compressedNBytes)
  err = ctstretch.CompressBytes(b[:n], compressed, rr.Decoder.expandedBlockBits, rr.Decoder.compressedBlockBits, rr.Decoder.revTable16, rr.Decoder.revTable8, rr.Decoder.readStream)
  if err != nil {
    log.Debugf(err.Error())
    return 0, err
  }
  copy(b[:compressedNBytes], compressed[:])
  log.Debugf("Riverrun: <- %d", n)
  return int(compressedNBytes), err
}
