package riverrun

import (
  "io"
  "bytes"
  "net"
  "fmt"
  "crypto/aes"
  "crypto/cipher"
  "math/rand"
  "gitlab.com/yawning/obfs4.git/common/drbg"
  "gitlab.com/yawning/obfs4.git/common/log"
  "gitlab.com/yawning/obfs4.git/common/ctstretch"
  "gitlab.com/yawning/obfs4.git/common/framing"
  "gitlab.com/yawning/obfs4.git/common/csrand"
  "encoding/binary"
)

// Implements the net.Conn interface
type RiverrunConn struct {
  // Embeds a net.Conn and inherits its members.

  net.Conn

  receiveBuffer        *bytes.Buffer
	receiveDecodedBuffer *bytes.Buffer
	readBuffer           []byte

	encoder *RiverrunEncoder
	decoder *RiverrunDecoder

  bias float64
}

func NewRiverrunConn(conn net.Conn, isServer bool, seed *drbg.Seed) (*RiverrunConn, error) {
  // FIXME: Bias was arbitrarily selected
  bias := float64(0.55)

  drbg, _ := drbg.NewHashDrbg(seed)
	rng := rand.New(drbg)
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

  var encoder *RiverrunEncoder
  var decoder *RiverrunDecoder
  // XXX: The only distinction between the read and write streams is the iv... is this secure?
  if isServer {
    readStream := stream
    rng.Read(iv)
    writeStream := cipher.NewCTR(block, iv)
    rng.Read(iv)
    encoder = NewEncoder(iv, compressedBlockBits, expandedBlockBits, writeStream, table8, table16)
    rng.Read(iv)
    decoder = NewDecoder(iv, compressedBlockBits, expandedBlockBits, readStream, ctstretch.InvertTable(table8), ctstretch.InvertTable(table16))
  } else {
    writeStream := stream
    rng.Read(iv)
    readStream := cipher.NewCTR(block, iv)
    rng.Read(iv)
    decoder = NewDecoder(iv, compressedBlockBits, expandedBlockBits, readStream, ctstretch.InvertTable(table8), ctstretch.InvertTable(table16))
    rng.Read(iv)
    encoder = NewEncoder(iv, compressedBlockBits, expandedBlockBits, writeStream, table8, table16)
  }

  rr := &RiverrunConn{conn, bytes.NewBuffer(nil), bytes.NewBuffer(nil), make([]byte, framing.ConsumeReadSize), encoder, decoder, bias}
  return rr, nil
}

func (conn *RiverrunConn) makePacket(w io.Writer, pktType uint8, data []byte) error {
  if len(data) > conn.encoder.maxPacketPayloadLength {
		panic(fmt.Sprintf("BUG: packet.Make() len(data) > maxPacketPayloadLength: %d > %d",
			len(data), conn.encoder.maxPacketPayloadLength))
	}

  // Encode the packet in a frame.
	var frame [framing.MaximumSegmentLength]byte
	frameLen, err := conn.encoder.Encode(frame[:], data, pktType)
  log.Debugf("Meke: Encoded frame of len %d", frameLen)
	if err != nil {
		// All encoder errors are fatal.
		return err
	}
	wrLen, err := w.Write(frame[:frameLen])
	if err != nil {
		return err
	} else if wrLen < frameLen {
		return io.ErrShortWrite
	}

	return nil
}

const (
	packetTypePayload = iota
)

// Decoding

type RiverrunDecoder struct {
  compressedBlockBits uint64
  expandedBlockBits uint64
  stream cipher.Stream
  revTable8 map[uint64]uint64
  revTable16 map[uint64]uint64

  // f.Decoder items
	drbg *drbg.HashDrbg
  maxPacketPayloadLength int
  minFrameLength int // = decoder.FrameOverhead(0)
  expandedLenNBytes int

	nextLength uint16
	nextLengthInvalid bool
}


func NewDecoder(key []byte, compressedBlockBits, expandedBlockBits uint64, stream cipher.Stream, revTable8, revTable16 map[uint64]uint64) *RiverrunDecoder {
  decoder := new(RiverrunDecoder)
  decoder.stream = stream
  decoder.revTable8 = revTable8
  decoder.revTable16 = revTable16
  decoder.compressedBlockBits = compressedBlockBits
  decoder.expandedBlockBits = expandedBlockBits
  decoder.minFrameLength = decoder.frameOverhead(0)
  decoder.maxPacketPayloadLength = int(ctstretch.CompressedNBytes(uint64(framing.MaximumSegmentLength - decoder.expandedLenNBytes), expandedBlockBits, compressedBlockBits))
  seed := make([]byte, drbg.SeedLength)
  copy(seed, key)
  decoder.drbg, _ = framing.Gendrbg(seed)
  decoder.expandedLenNBytes = int(ctstretch.ExpandedNBytes(framing.LengthLength, compressedBlockBits, expandedBlockBits))
  return decoder
}

func (decoder *RiverrunDecoder) frameOverhead(payloadLen int) int {
  return decoder.expandedLenNBytes + int(ctstretch.ExpandedNBytes(uint64(payloadLen), decoder.compressedBlockBits, decoder.expandedBlockBits)) - payloadLen
}

func (decoder *RiverrunDecoder) decode(data []byte, frames *bytes.Buffer) (int, error) {
  n, frame, err := decoder.getFrame(frames)
  if err != nil {
    return 0, err
  }

  // Decode
  compressedNBytes := ctstretch.CompressedNBytes(uint64(n), decoder.expandedBlockBits, decoder.compressedBlockBits)
  data = make([]byte, compressedNBytes)
  err = ctstretch.CompressBytes(frame[:n], data[:], decoder.expandedBlockBits, decoder.compressedBlockBits, decoder.revTable16, decoder.revTable8, decoder.stream)
  if err != nil {
    return 0, err
  }
  log.Debugf("Riverrun: <- %d", n)

  if decoder.nextLengthInvalid {
    return 0, framing.ErrTagMismatch
  }

  decoder.nextLength = 0
  return int(compressedNBytes), nil
}

func (decoder *RiverrunDecoder) ParseLength(rawLengthBytes []byte) (uint16, error) {
  lengthBytes := make([]byte, framing.LengthLength)
  err := ctstretch.CompressBytes(rawLengthBytes, lengthBytes, decoder.expandedBlockBits, decoder.compressedBlockBits, decoder.revTable16, decoder.revTable8, decoder.stream)
  if err != nil {
    return 0, err
  }
	return binary.BigEndian.Uint16(lengthBytes[:]), nil
}

// Encoding

type RiverrunEncoder struct {
  expandedLenNBytes int
  compressedBlockBits uint64
  expandedBlockBits uint64
  stream cipher.Stream
  table8 []uint64
  table16 []uint64
  // f.Decoder items
	drbg *drbg.HashDrbg
  maxPacketPayloadLength int
  maxFramePayloadLength int
}

func NewEncoder(key []byte, compressedBlockBits, expandedBlockBits uint64, stream cipher.Stream, table8, table16 []uint64) *RiverrunEncoder {
  encoder := new(RiverrunEncoder)
  encoder.stream = stream
  encoder.table8 = table8
  encoder.table16 = table16
  encoder.compressedBlockBits = compressedBlockBits
  encoder.expandedBlockBits = expandedBlockBits
  encoder.expandedLenNBytes = int(ctstretch.ExpandedNBytes(framing.LengthLength, compressedBlockBits, expandedBlockBits))
  encoder.maxPacketPayloadLength = int(ctstretch.CompressedNBytes(uint64(framing.MaximumSegmentLength - encoder.expandedLenNBytes), expandedBlockBits, compressedBlockBits))
  encoder.maxFramePayloadLength = encoder.maxPacketPayloadLength
  seed := make([]byte, drbg.SeedLength)
  copy(seed, key)
  encoder.drbg, _ = framing.Gendrbg(seed)
  return encoder
}

func (encoder *RiverrunEncoder) FrameOverhead(payloadLen int) int {
  return encoder.expandedLenNBytes + int(ctstretch.ExpandedNBytes(uint64(payloadLen), encoder.compressedBlockBits, encoder.expandedBlockBits)) - payloadLen
}

func (encoder *RiverrunEncoder) check(payloadLen, frameLen int) error {
	if encoder.maxFramePayloadLength < payloadLen {
		return framing.InvalidPayloadLengthError(payloadLen)
	}
	if frameLen < payloadLen+encoder.FrameOverhead(payloadLen) {
		return io.ErrShortBuffer
	}
	return nil
}

func (encoder *RiverrunEncoder) Encode(frame, payload []byte, pktType uint8) (n int, err error) {
  // TODO: Panic if pkttype is not 0

  if err = encoder.check(len(payload), len(frame)); err != nil {
		return 0, err
	}

  // Obfuscate the length and modify the entropy
  length := uint16(ctstretch.ExpandedNBytes(uint64(len(payload)), encoder.compressedBlockBits, encoder.expandedBlockBits))
	oLength := length ^ binary.BigEndian.Uint16(encoder.drbg.NextBlock())
  oBytes := make([]byte, 2)
  binary.BigEndian.PutUint16(oBytes, oLength)
  err = ctstretch.ExpandBytes(oBytes, frame[:encoder.expandedLenNBytes], encoder.compressedBlockBits, encoder.expandedBlockBits, encoder.table16, encoder.table8, encoder.stream)
  if err != nil {
    return 0, err
  }

  // Expand the payload.
  err = ctstretch.ExpandBytes(payload, frame[encoder.expandedLenNBytes:], encoder.compressedBlockBits, encoder.expandedBlockBits, encoder.table16, encoder.table8, encoder.stream)
  if err != nil {
    return 0, err
  }

	// Return the frame.
	return int(length)+encoder.expandedLenNBytes, nil
}

func (conn *RiverrunConn) readPacket(pkt []byte) (err error) {
  conn.receiveDecodedBuffer.Write(pkt)
	return
}

func (rr *RiverrunConn) Write(b []byte) (n int, err error) {
  var frameBuf bytes.Buffer

	frameBuf, n, err = rr.Chop(b, packetTypePayload)
  if err != nil {
		return 0, err
	}

  _, err = rr.Conn.Write(frameBuf.Bytes())
  log.Debugf("Wrote %d", n)
  return
}

// Chop the pending data into payload frames.
func (conn *RiverrunConn) Chop(b []byte, pktType uint8) (frameBuf bytes.Buffer, n int, err error) {
	chopBuf := bytes.NewBuffer(b)
	payload := make([]byte, conn.encoder.maxPacketPayloadLength)

	for chopBuf.Len() > 0 {
		// Send maximum sized frames.
		rdLen := 0
		rdLen, err = chopBuf.Read(payload[:])
		if err != nil {
			return frameBuf, 0, err
		} else if rdLen == 0 {
			panic(fmt.Sprintf("BUG: Write(), chopping length was 0"))
		}
		n += rdLen

    err = conn.makePacket(&frameBuf, pktType, payload[:rdLen])
		if err != nil {
			return frameBuf, 0, err
		}
	}
	return
}

func (decoder *RiverrunDecoder) getFrame(frames *bytes.Buffer) (int, []byte, error) {
  if decoder.nextLength == 0 {
    // Attempt to pull out the next frame length.
  	if decoder.expandedLenNBytes > frames.Len() {
  		return 0, nil, framing.ErrAgain
  	}
  	// Remove the length field from the buffer.
  	rawLengthBytes := make([]byte, decoder.expandedLenNBytes)
  	_, err := io.ReadFull(frames, rawLengthBytes[:])
  	if err != nil {
  		return 0, nil, err
  	}
    // Parse length
    length, err := decoder.ParseLength(rawLengthBytes)
    if err != nil {
  		return 0, nil, err
  	}
  	// Deobfuscate the length field.
    drbg := decoder.drbg
  	lengthMask := drbg.NextBlock()
  	length ^= binary.BigEndian.Uint16(lengthMask)
  	if framing.MaxFrameLength < length || decoder.minFrameLength - framing.LengthLength > int(length) {
  		// Per "Plaintext Recovery Attacks Against SSH" by
  		// Martin R. Albrecht, Kenneth G. Paterson and Gaven J. Watson,
  		// there are a class of attacks againt protocols that use similar
  		// sorts of framing schemes.
  		//
  		// While obfs4 should not allow plaintext recovery (CBC mode is
  		// not used), attempt to mitigate out of bound frame length errors
  		// by pretending that the length was a random valid range as per
  		// the countermeasure suggested by Denis Bider in section 6 of the
  		// paper.
      decoder.nextLength = uint16(csrand.IntRange(decoder.minFrameLength - framing.LengthLength, framing.MaxFrameLength))
      decoder.nextLengthInvalid = true
  	} else {
      log.Debugf("GetFrame: Decoder set next length: %d", length)
      decoder.nextLength = length
      decoder.nextLengthInvalid = false // TODO: This doesn't always need to be set
    }
	}
	if int(decoder.nextLength) > frames.Len() {
		return 0, nil, framing.ErrAgain
	}
  frame := make([]byte, decoder.nextLength)
  n, err := io.ReadFull(frames, frame[:])
  log.Debugf("GetFrame: Next read length: %d", n)
  if err != nil {
    return 0, nil, err
  }
  return n, frame, nil
}

func (conn *RiverrunConn) Read(b []byte) (n int, err error) {
	// If there is no payload from the previous Read() calls, consume data off
	// the network.  Not all data received is guaranteed to be usable payload,
	// so do this in a loop till data is present or an error occurs.
	for conn.receiveDecodedBuffer.Len() == 0 {
		err = conn.readPackets()
		if err == framing.ErrAgain {
			// Don't proagate this back up the call stack if we happen to break
			// out of the loop.
			err = nil
			continue
		} else if err != nil {
			break
		}
	}

	// Even if err is set, attempt to do the read anyway so that all decoded
	// data gets relayed before the connection is torn down.
	if conn.receiveDecodedBuffer.Len() > 0 {
		var berr error
		n, berr = conn.receiveDecodedBuffer.Read(b)
		if err == nil {
			// Only propagate berr if there are not more important (fatal)
			// errors from the network/crypto/packet processing.
			err = berr
		}
	}
  log.Debugf("Read: Read %d", n)
	return
}

func (conn *RiverrunConn) readPackets() (err error) {
  // Attempt to read off the network.
	rdLen, rdErr := conn.Conn.Read(conn.readBuffer)
	conn.receiveBuffer.Write(conn.readBuffer[:rdLen])
	decoded := make([]byte, conn.decoder.maxPacketPayloadLength)
	for conn.receiveBuffer.Len() > 0 {
		decLen := 0
		decLen, err = conn.decoder.decode(decoded[:], conn.receiveBuffer)
		if err != nil {
			break
		}
    log.Debugf("ReadPackets: Decoded length is %d", decLen)
    err = conn.readPacket(decoded[:decLen])
    if err != nil {
      break
    }
	}

	// Read errors (all fatal) take priority over various frame processing
	// errors.
	if rdErr != nil {
		return rdErr
	}
	return
}
