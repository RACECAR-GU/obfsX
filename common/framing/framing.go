
package framing

import (
  "fmt"
  "errors"
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

// BaseEncoder implements the core encoder vars and functions
type BaseEncoder struct {
  Drbg *drbg.HashDrbg
}

// ObfuscateLength creates a mask and obfuscates the payloads length
func (encoder *BaseEncoder) ObfuscateLength(frame []byte, length uint16) {
	lengthMask := encoder.Drbg.NextBlock()
	length ^= binary.BigEndian.Uint16(lengthMask)
	binary.BigEndian.PutUint16(frame[:2], length)
}