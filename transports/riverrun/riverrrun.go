package riverrun

import (
  "bytes"
  "net"
  "crypto/aes"
  "crypto/cipher"
  "math/rand"
  "gitlab.com/yawning/obfs4.git/common/ctstretch"
)

// Implements the net.Conn interface
type RiverrunConn struct {
  // Embeds a net.Conn and inherits its members.
  net.Conn

  bias float64

  stream cipher.Stream

  table8 map[uint64]uint64
  table16 map[uint64]uint64
  revTable8 map[uint64]uint64
  revTable16 map[uint64]uint64

  compressedBlockBits uint64
  expandedBlockBits uint64
}

func NewRiverrunConn(conn net.Conn, seed *drbg.Seed) *RiverrunConn {
  // FIXME: Bias was arbitrarily selected
  bias := float64(0.55)

  drbg, _ := drbg.NewHashDrbg(seed)
	rng := rand.New(drbg)
  key := make([]byte, 16)
	rng.Read(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

  iv := make([]byte, block.BlockSize())
	rng.Read(iv)

  stream := cipher.NewCTR(block, iv)

  // FIXME: Input and output block bits are randomly selected from valid options,
  //        there may be a more optimal selection methedology/initial subset
  compressedBlockBits := uint64((rng.Intn(2)+1) * 8)

  var expandedBlockBits8 uint64
	if compressedBlockBits == 8 {
		expandedBlockBits8 = uint64((rng.Intn(7)+2) * 8)
	} else {
		expandedBlockBits8 = uint64((rng.Intn(3)+2) * 16)
	}

  table8 := ctstretch.SampleBiasedStrings(expandedBlockBits8, 256, bias, stream)
  table16 := ctstretch.SampleBiasedStrings(expandedBlockBits, 65536, bias, stream)

  rr := &RiverrunConn{conn, bias, stream, table8, table16, ctstretch.InvertTable(table8), ctstretch.InvertTable(table16), compressedBlockBits, expandedBlockBits}
}

func (rr *RiverrunConn) Write(b []byte) (int, error) {
  expandedNBytes := ctstretch.ExpandedNBytes(len(b), rr.compressedBlockBits, rr.expandedBlockBits)

  expanded := make([]byte, expandedNBytes)
  ctstretch.ExpandBytes(b[:], expanded, rr.compressedBlockBits, rr.expandedBlockBits, rr.table16, rr.table8, rr.streamClient)
  n, err := rr.Conn.Write(expanded)
  log.Debugf("%d ->", n)
  return n, err
}

func (rr *RiverrunConn) Read(b []byte) (int, error) {
  compressedNBytes := ctstretch.CompressedNBytes(len(b), rr.expandedBlockBits, rr.compressedBlockBits)
  compressed := make([]byte, compressedNBytes)

  ctstretch.CompressBytes(b, compressed, rr.expandedBlockBits, rr.compressedBlockBits, rr.revTable16, rr.revTable8, rr.streamServer)
  n, err := rr.Conn.Read(compressed)
  log.Debugf("<- %d", n)
  return n, err
}
