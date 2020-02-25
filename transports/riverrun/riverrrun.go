package riverrun

import (
  "net"
  "crypto/aes"
  "crypto/cipher"
  "math/rand"
  "gitlab.com/yawning/obfs4.git/common/drbg"
  "gitlab.com/yawning/obfs4.git/common/log"
  "gitlab.com/yawning/obfs4.git/common/ctstretch"
)

// Implements the net.Conn interface
type RiverrunConn struct {
  // Embeds a net.Conn and inherits its members.
  net.Conn

  bias float64

  readStream cipher.Stream
  writeStream cipher.Stream

  table8 []uint64
  table16 []uint64
  revTable8 map[uint64]uint64
  revTable16 map[uint64]uint64

  compressedBlockBits uint64
  expandedBlockBits uint64
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

  var readStream, writeStream cipher.Stream
  // XXX: The only distinction between the read and write streams is the iv... is this secure?
  if isServer {
    readStream = stream
    rng.Read(iv)
    writeStream = cipher.NewCTR(block, iv)
  } else {
    writeStream = stream
    rng.Read(iv)
    readStream = cipher.NewCTR(block, iv)
  }
  rr := &RiverrunConn{conn, bias, readStream, writeStream, table8, table16, ctstretch.InvertTable(table8), ctstretch.InvertTable(table16), compressedBlockBits, expandedBlockBits}
  return rr, nil
}

func (rr *RiverrunConn) Write(b []byte) (int, error) {
  expandedNBytes := ctstretch.ExpandedNBytes(uint64(len(b)), rr.compressedBlockBits, rr.expandedBlockBits)

  expanded := make([]byte, expandedNBytes)
  err := ctstretch.ExpandBytes(b[:], expanded, rr.compressedBlockBits, rr.expandedBlockBits, rr.table16, rr.table8, rr.writeStream)
  if err != nil {
    return 0, nil
  }
  n, err := rr.Conn.Write(expanded)
  log.Debugf("Riverrun: %d expanded to %d ->", len(b), n)
  return n, err
}

func (rr *RiverrunConn) Read(b []byte) (int, error) {
  n, err := rr.Conn.Read(b)
  if err != nil {
    return n, err
  }
  compressedNBytes := ctstretch.CompressedNBytes(uint64(n), rr.expandedBlockBits, rr.compressedBlockBits)
  compressed := make([]byte, compressedNBytes)
  err = ctstretch.CompressBytes(b[:n], compressed, rr.expandedBlockBits, rr.compressedBlockBits, rr.revTable16, rr.revTable8, rr.readStream)
  if err != nil {
    log.Debugf(err.Error())
    return 0, err
  }
  copy(b[:compressedNBytes], compressed[:])
  log.Debugf("Riverrun: <- %d", n)
  return int(compressedNBytes), err
}
