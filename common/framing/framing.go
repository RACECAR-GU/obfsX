
package framing

import (
  "io"
  "fmt"
  "errors"
  "bytes"
  "encoding/binary"

  "gitlab.com/yawning/obfs4.git/common/drbg"
)

const (
  // MaximumSegmentLength is the length of the largest possible segment
	// including overhead.
	MaximumSegmentLength = 1500 - 52

  // LengthLength is the number of bytes used to represent length
  LengthLength = 2

  // TypeLength is the number of bytes used to indicate packet type
  TypeLength = 1

  // MaxFrameLength is the maximum frame length
  MaxFrameLength = MaximumSegmentLength - LengthLength

  ConsumeReadSize = MaximumSegmentLength * 16
)

// ErrAgain is the error returned when decoding requires more data to continue.
var ErrAgain = errors.New("framing: More data needed to decode")

// Error returned when Decoder.Decode() failes to authenticate a frame.
var ErrTagMismatch = errors.New("framing: Poly1305 tag mismatch")

// InvalidPayloadLengthError is the error returned when Encoder.Encode()
// rejects the payload length.
type InvalidPayloadLengthError int
func (e InvalidPayloadLengthError) Error() string {
	return fmt.Sprintf("framing: Invalid payload length: %d", int(e))
}

/*
func Gendrbg(key []byte) (*drbg.HashDrbg, error) {
  seed, err := drbg.SeedFromBytes(key)
	if err != nil {
		panic(fmt.Sprintf("BUG: Failed to initialize DRBG: %s", err))
	}
  return drbg.NewHashDrbg(seed)
}
*/

type encodeFunc func(frame, payload []byte) (n int, err error)
type chopPayloadFunc func(pktType uint8, payload []byte) []byte
type payloadOverheadFunc func(payloadLen int) int

// BaseEncoder implements the core encoder vars and functions
type BaseEncoder struct {
  Drbg *drbg.HashDrbg
  MaxPacketPayloadLength int

  PayloadOverhead payloadOverheadFunc

  Encode encodeFunc
  ChopPayload chopPayloadFunc
}

func (encoder *BaseEncoder) MakePacket(w io.Writer, payload []byte) error {
	// Encode the packet in an AEAD frame.
	var frame [MaximumSegmentLength]byte
  payloadLen := len(payload)
  if len(frame) < payloadLen+encoder.PayloadOverhead(payloadLen) {
		return io.ErrShortBuffer
	}
	frameLen, err := encoder.Encode(frame[LengthLength:], payload[:payloadLen])
	if err != nil {
		// All encoder errors are fatal.
		return err
	}

  length := uint16(frameLen)
  lengthMask := encoder.Drbg.NextBlock()
	length ^= binary.BigEndian.Uint16(lengthMask)
	binary.BigEndian.PutUint16(frame[:LengthLength], length)

	wrLen, err := w.Write(frame[:LengthLength + frameLen])
	if err != nil {
		return err
	} else if wrLen < frameLen {
		return io.ErrShortWrite
	}

	return nil
}

// Chop the pending data into payload frames.
func (encoder *BaseEncoder) Chop(b []byte, pktType uint8) (frameBuf bytes.Buffer, n int, err error) {
	chopBuf := bytes.NewBuffer(b)
	payload := make([]byte, encoder.MaxPacketPayloadLength)
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
    err = encoder.MakePacket(&frameBuf, encoder.ChopPayload(pktType, payload[:rdLen]))
		if err != nil {
			return frameBuf, 0, err
		}
	}
	return
}

// GenDrbg creates a *drbg.HashDrbg with some safety checks
func GenDrbg(key []byte) *drbg.HashDrbg {
  if len(key) != drbg.SeedLength {
    panic(fmt.Sprintf("BUG: Failed to initialize DRBG: Invalid Keylength, must be %n (drbg.SeedLength)", drbg.SeedLength))
  }
  seed, err := drbg.SeedFromBytes(key[:])
	if err != nil {
		panic(fmt.Sprintf("BUG: Failed to initialize DRBG: %s", err))
	}
  res, err := drbg.NewHashDrbg(seed)
  if err != nil {
		panic(fmt.Sprintf("BUG: Failed to initialize DRBG: %s", err))
	}
  return res
}
