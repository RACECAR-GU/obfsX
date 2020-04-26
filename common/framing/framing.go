
package framing

import (
  "io"
  "fmt"
  "errors"
  "bytes"
  "net"
  "encoding/binary"

  "gitlab.com/yawning/obfs4.git/common/drbg"
  "gitlab.com/yawning/obfs4.git/common/csrand"
  "gitlab.com/yawning/obfs4.git/common/log"
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
  // MaxFrameLength = MaximumSegmentLength - LengthLength

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

// InvalidPacketLengthError is the error returned when decodePacket detects a
// invalid packet length/
type InvalidPacketLengthError int
func (e InvalidPacketLengthError) Error() string {
	return fmt.Sprintf("packet: Invalid packet length: %d", int(e))
}

type encodeFunc func(frame, payload []byte) (n int, err error)
type chopPayloadFunc func(pktType uint8, payload []byte) []byte
type overheadFunc func(payloadLen int) int
type processLengthFunc func(length uint16) ([]byte, error)

// BaseEncoder implements the core encoder vars and functions
type BaseEncoder struct {
  Drbg *drbg.HashDrbg
  MaxPacketPayloadLength int
  LengthLength int
  PayloadOverhead overheadFunc

  Encode encodeFunc
  ProcessLength processLengthFunc
  ChopPayload chopPayloadFunc

  Type  string
}

// TODO: Only do this for riverrun encoder

func (encoder *BaseEncoder) MakePacket(w io.Writer, payload []byte) error {
	// Encode the packet in an AEAD frame.
	var frame [MaximumSegmentLength]byte
  payloadLen := len(payload)
  if encoder.Type == "rr" {
      log.Debugf("Make: Raw payloadLen: %d", payloadLen)
  }
  payloadLenWithOverhead0 := payloadLen+encoder.PayloadOverhead(payloadLen)
  if len(frame) - encoder.LengthLength < payloadLenWithOverhead0 {
		return io.ErrShortBuffer
	}
  length := uint16(payloadLenWithOverhead0)
  if encoder.Type == "rr" {
    log.Debugf("Make: PayloadLenWithOverhead: %d", length)
  }
  lengthMask := encoder.Drbg.NextBlock()
	length ^= binary.BigEndian.Uint16(lengthMask)
  if encoder.Type == "rr" {
    log.Debugf("Make: Length ID %d", length)
  }
  processedLength, err := encoder.ProcessLength(length)
  if err != nil {
    return err
  }
	copy(frame[:encoder.LengthLength], processedLength)
  frameLen := encoder.LengthLength + payloadLenWithOverhead0
	payloadLenWithOverhead1, err := encoder.Encode(frame[encoder.LengthLength:], payload[:payloadLen])
	if err != nil {
		// All encoder errors are fatal.
		return err
	}

  if payloadLenWithOverhead0 != payloadLenWithOverhead1 {
    panic(fmt.Sprintf("BUG: MakePacket(), frame lengths do not align, %d %d", payloadLenWithOverhead0, payloadLenWithOverhead1))
  }

	wrLen, err := w.Write(frame[:frameLen])
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
			panic(fmt.Sprintf("BUG: Chop(), chopping length was 0"))
		}
		n += rdLen
    err = encoder.MakePacket(&frameBuf, encoder.ChopPayload(pktType, payload[:rdLen]))
		if err != nil {
			return frameBuf, 0, err
		}
	}
	return
}

type decodeLengthfunc func(lengthBytes []byte) (uint16, error)
type decodePayloadfunc func(frames *bytes.Buffer) ([]byte, error)
type parsePacketFunc func(decoded []byte, decLen int) error
type cleanupfunc func() error
type BaseDecoder struct {
  Drbg *drbg.HashDrbg
  LengthLength int
  MinPayloadLength int
  PacketOverhead int
  MaxFramePayloadLength int

  NextLength uint16
  NextLengthInvalid bool

  PayloadOverhead overheadFunc

  DecodeLength decodeLengthfunc
  DecodePayload decodePayloadfunc
  ParsePacket parsePacketFunc
  Cleanup cleanupfunc

  ReceiveBuffer        *bytes.Buffer
  ReceiveDecodedBuffer *bytes.Buffer
  readBuffer           []byte
}
func (decoder *BaseDecoder) InitBuffers() {
  decoder.ReceiveBuffer = bytes.NewBuffer(nil)
  decoder.ReceiveDecodedBuffer = bytes.NewBuffer(nil)
  decoder.readBuffer = make([]byte, ConsumeReadSize)
}

func (decoder *BaseDecoder) GetFrame(frames *bytes.Buffer) (int, []byte, error) {
	maximumPayloadLength := MaximumSegmentLength - decoder.LengthLength
  singleFrame := make([]byte, maximumPayloadLength)
  n, err := io.ReadFull(frames, singleFrame[:decoder.NextLength])
	if err != nil {
		return 0, nil, err
	}
	return n, singleFrame, nil
}

func (decoder *BaseDecoder) Read(b []byte, conn net.Conn) (n int, err error) {
  // If there is no payload from the previous Read() calls, consume data off
	// the network.  Not all data received is guaranteed to be usable payload,
	// so do this in a loop till data is present or an error occurs.
	for decoder.ReceiveDecodedBuffer.Len() == 0 {
		err = decoder.readPackets(conn)
		if err == ErrAgain {
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
	if decoder.ReceiveDecodedBuffer.Len() > 0 {
		var berr error
		n, berr = decoder.ReceiveDecodedBuffer.Read(b)
		if err == nil {
			// Only propagate berr if there are not more important (fatal)
			// errors from the network/crypto/packet processing.
			err = berr
		}
	}

	return
}

func (decoder *BaseDecoder) readPackets(conn net.Conn) (err error) {
	// Attempt to read off the network.
	rdLen, rdErr := conn.Read(decoder.readBuffer)
	decoder.ReceiveBuffer.Write(decoder.readBuffer[:rdLen])

	decoded := make([]byte, decoder.MaxFramePayloadLength)
	for decoder.ReceiveBuffer.Len() > 0 {
		// Decrypt an AEAD frame.
		decLen := 0
		decLen, err = decoder.Decode(decoded[:], decoder.ReceiveBuffer)
		if err == ErrAgain {
			break
		} else if err != nil {
			break
		} else if decLen < decoder.PacketOverhead {
			err = InvalidPacketLengthError(decLen)
			break
		}

    err = decoder.ParsePacket(decoded, decLen)
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

// Decode decodes a stream of data and returns the length if any.  ErrAgain is
// a temporary failure, all other errors MUST be treated as fatal and the
// session aborted.
func (decoder *BaseDecoder) Decode(data []byte, frames *bytes.Buffer) (int, error) {

	// A length of 0 indicates that we do not know how big the next frame is
	// going to be.
	if decoder.NextLength == 0 {
		// Attempt to pull out the next frame length.
		if decoder.LengthLength > frames.Len() {
			return 0, ErrAgain
		}

		lengthlength := make([]byte, decoder.LengthLength)
	  _, err := io.ReadFull(frames, lengthlength[:])
	  if err != nil {
	    return 0, err
	  }
	  // Deobfuscate the length field.
	  length, err := decoder.DecodeLength(lengthlength)
    // HACK: If this works...
    //       This is preventing the error from arising, but it gets stuck...
    if length == 0 {
      log.Debugf("In the hack!")
      return 0, ErrAgain
    }
    if err != nil {
      return 0, err
    }
	  lengthMask := decoder.Drbg.NextBlock()
    log.Debugf("length id: %d", length)
	  length ^= binary.BigEndian.Uint16(lengthMask)
    log.Debugf("First nextLength: %d", length)
	  if MaximumSegmentLength - int(decoder.LengthLength) < int(length) || decoder.MinPayloadLength > int(length) {
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
      log.Debugf("Bad length")
	    decoder.NextLengthInvalid = true
	    length = uint16(csrand.IntRange(decoder.MinPayloadLength, MaximumSegmentLength - int(decoder.LengthLength)))
	  }
    log.Debugf("Out nextLength: %d", length)
	  decoder.NextLength = length
	}

	if int(decoder.NextLength) > frames.Len() {
		return 0, ErrAgain
	}

  decodedPayload, err := decoder.DecodePayload(frames)
	if err != nil {
		return 0, err
	}
	copy(data[0:len(decodedPayload)], decodedPayload[:])

	if decoder.NextLengthInvalid {
		// When a random length is used be paranoid.
		return 0, ErrTagMismatch
	}

	// Clean up and prepare for the next frame.
	decoder.NextLength = 0
	return len(decodedPayload), decoder.Cleanup()
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
