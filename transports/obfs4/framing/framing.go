/*
 * Copyright (c) 2014, Yawning Angel <yawning at schwanenlied dot me>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

//
// Package framing implements the obfs4 link framing and cryptography.
//
// The ObfsEncoder/ObfsDecoder shared secret format is:
//    uint8_t[32] NaCl secretbox key
//    uint8_t[16] NaCl Nonce prefix
//    uint8_t[16] SipHash-2-4 key (used to obfsucate length)
//    uint8_t[8]  SipHash-2-4 IV
//
// The frame format is:
//   uint16_t length (obfsucated, big endian)
//   NaCl secretbox (Poly1305/XSalsa20) containing:
//     uint8_t[16] tag (Part of the secretbox construct)
//     uint8_t[]   payload
//
// The length field is length of the NaCl secretbox XORed with the truncated
// SipHash-2-4 digest ran in OFB mode.
//
//     Initialize K, IV[0] with values from the shared secret.
//     On each packet, IV[n] = H(K, IV[n - 1])
//     mask[n] = IV[n][0:2]
//     obfsLen = length ^ mask[n]
//
// The NaCl secretbox (Poly1305/XSalsa20) nonce format is:
//     uint8_t[24] prefix (Fixed)
//     uint64_t    counter (Big endian)
//
// The counter is initialized to 1, and is incremented on each frame.  Since
// the protocol is designed to be used over a reliable medium, the nonce is not
// transmitted over the wire as both sides of the conversation know the prefix
// and the initial counter value.  It is imperative that the counter does not
// wrap, and sessions MUST terminate before 2^64 frames are sent.
//
package framing // import "gitlab.com/yawning/obfs4.git/transports/obfs4/framing"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"gitlab.com/yawning/obfs4.git/common/drbg"
	f "gitlab.com/yawning/obfs4.git/common/framing"
	"golang.org/x/crypto/nacl/secretbox"
)

const (

	// FrameOverhead is the length of the framing overhead.
	FrameOverhead = f.LengthLength + secretbox.Overhead

	// MaximumFramePayloadLength is the length of the maximum allowed payload
	// per frame.
	MaximumFramePayloadLength = f.MaximumSegmentLength - FrameOverhead

	// KeyLength is the length of the ObfsEncoder/ObfsDecoder secret key.
	KeyLength = keyLength + noncePrefixLength + drbg.SeedLength

	minFrameLength = FrameOverhead - f.LengthLength

	keyLength = 32

	noncePrefixLength  = 16
	nonceCounterLength = 8
	nonceLength        = noncePrefixLength + nonceCounterLength
)

const (
	PacketTypePayload = iota
	PacketTypePrngSeed
)

// Error returned when the NaCl secretbox nonce's counter wraps (FATAL).
var ErrNonceCounterWrapped = errors.New("framing: Nonce counter wrapped")

type boxNonce struct {
	prefix  [noncePrefixLength]byte
	counter uint64
}

func (nonce *boxNonce) init(prefix []byte) {
	if noncePrefixLength != len(prefix) {
		panic(fmt.Sprintf("BUG: Nonce prefix length invalid: %d", len(prefix)))
	}

	copy(nonce.prefix[:], prefix)
	nonce.counter = 1
}

func (nonce boxNonce) bytes(out *[nonceLength]byte) error {
	// The security guarantee of Poly1305 is broken if a nonce is ever reused
	// for a given key.  Detect this by checking for counter wraparound since
	// we start each counter at 1.  If it ever happens that more than 2^64 - 1
	// frames are transmitted over a given connection, support for rekeying
	// will be neccecary, but that's unlikely to happen.
	if nonce.counter == 0 {
		return ErrNonceCounterWrapped
	}

	copy(out[:], nonce.prefix[:])
	binary.BigEndian.PutUint64(out[noncePrefixLength:], nonce.counter)

	return nil
}

// ObfsEncoder is a frame encoder instance.
type ObfsEncoder struct {
	f.BaseEncoder
	key   [keyLength]byte
	nonce boxNonce
	PacketOverhead int
}
func (encoder *ObfsEncoder) payloadOverhead(_ int) int {
	return secretbox.Overhead
}

func (encoder *ObfsEncoder) processLength(length uint16) []byte {
	lengthBytes := make([]byte, encoder.LengthLength)
	binary.BigEndian.PutUint16(lengthBytes[:], length)
	return lengthBytes
}


// NewObfsEncoder creates a new ObfsEncoder instance.  It must be supplied a slice
// containing exactly KeyLength bytes of keying material.
func NewObfsEncoder(key []byte) *ObfsEncoder {

	if len(key) != KeyLength {
		panic(fmt.Sprintf("BUG: Invalid encoder key length: %d", len(key)))
	}

	encoder := new(ObfsEncoder)

	encoder.Drbg = f.GenDrbg(key[keyLength+noncePrefixLength:])
	// encoder.MaxPacketPayloadLength is set in obfs4.go
	encoder.LengthLength = 2
	encoder.PayloadOverhead = encoder.payloadOverhead

	encoder.Encode = encoder.encode
	encoder.ProcessLength = encoder.processLength
	// encoder.ChopPayload is set in obfs4.go

	copy(encoder.key[:], key[0:keyLength])
	encoder.nonce.init(key[keyLength : keyLength+noncePrefixLength])
	encoder.PacketOverhead = f.LengthLength + f.TypeLength

	return encoder
}

// Encode encodes a single frame worth of payload and returns the encoded
// length.  InvalidPayloadLengthError is recoverable, all other errors MUST be
// treated as fatal and the session aborted.
func (encoder *ObfsEncoder) encode(frame, payload []byte) (n int, err error) {
	// TODO: Consider generalizing these
	payloadLen := len(payload)
	if MaximumFramePayloadLength < payloadLen {
		return 0, f.InvalidPayloadLengthError(payloadLen)
	}

	// Generate a new nonce.
	var nonce [nonceLength]byte
	if err = encoder.nonce.bytes(&nonce); err != nil {
		return 0, err
	}
	encoder.nonce.counter++

	// Encrypt and MAC payload.
	box := secretbox.Seal(frame[:0], payload, &nonce, &encoder.key)

	// Return the frame.
	return len(box), nil
}

type prngRegenFunc func(payload []byte) error
// ObfsDecoder is a BaseDecoder instance.
type ObfsDecoder struct {
	f.BaseDecoder
	key   [keyLength]byte
	nonce boxNonce

	nextNonce         [nonceLength]byte

	PacketOverhead int
	PrngRegen prngRegenFunc
}
func (decoder *ObfsDecoder) payloadOverhead(_ int) int {
	return secretbox.Overhead
}

// NewObfsDecoder creates a new ObfsDecoder instance.  It must be supplied a slice
// containing exactly KeyLength bytes of keying material.
func NewObfsDecoder(key []byte) *ObfsDecoder {
	if len(key) != KeyLength {
		panic(fmt.Sprintf("BUG: Invalid decoder key length: %d", len(key)))
	}

	decoder := new(ObfsDecoder)

	decoder.Drbg = f.GenDrbg(key[keyLength+noncePrefixLength:])
	decoder.LengthLength = f.LengthLength
	decoder.MinPayloadLength = f.LengthLength + f.TypeLength
	decoder.MaxFramePayloadLength = MaximumFramePayloadLength

	// NextLength is set programatically
	// NextLengthInvalid is set programatically

	decoder.PayloadOverhead = decoder.payloadOverhead

	decoder.DecodeLength = decoder.decodeLength
	decoder.DecodePayload = decoder.decodePayload
	decoder.ParsePacket = decoder.parsePacket
	decoder.Cleanup = decoder.cleanup

	decoder.InitBuffers()

	copy(decoder.key[:], key[0:keyLength])
	decoder.nonce.init(key[keyLength : keyLength+noncePrefixLength])

	// nextNonce is programatically derived

	decoder.PacketOverhead = f.LengthLength + f.TypeLength
	// prngRegen is defined in obfs4.go

	return decoder
}

func (decoder *ObfsDecoder) decodeLength(lengthBytes []byte) uint16 {
	return binary.BigEndian.Uint16(lengthBytes[:decoder.LengthLength])
}

func (decoder *ObfsDecoder) decodePayload(frames *bytes.Buffer) ([]byte, error) {
	// Derive the nonce the peer used.
	err := decoder.nonce.bytes(&decoder.nextNonce)
	if err != nil {
		return nil, err
	}

	// Unseal the frame.
	maximumPayloadLength := f.MaximumSegmentLength - decoder.LengthLength
	box := make([]byte, maximumPayloadLength)
	holder := make([]byte, maximumPayloadLength) // TODO: Could be the max payload length
	n, err := io.ReadFull(frames, box[:decoder.NextLength])
	if err != nil {
		return nil, err
	}
	decodedPayload, ok := secretbox.Open(holder[:0], box[:n], &decoder.nextNonce, &decoder.key)
	if !ok {
		return nil, f.ErrTagMismatch
	}

	return decodedPayload, nil
}

func (decoder *ObfsDecoder) cleanup() error {
	decoder.nonce.counter++
	return nil
}

func (decoder *ObfsDecoder) parsePacket(decoded []byte, decLen int) error {
	// Decode the packet.
	pkt := decoded[0:decLen]
	pktType := pkt[0]
	payloadLen := binary.BigEndian.Uint16(pkt[1:])
	if int(payloadLen) > len(pkt)-decoder.PacketOverhead {
		return f.InvalidPayloadLengthError(int(payloadLen))
	}
	payload := pkt[f.TypeLength + f.LengthLength : f.TypeLength + f.LengthLength+payloadLen]

	switch pktType {
		case PacketTypePayload:
			if payloadLen > 0 {
				decoder.ReceiveDecodedBuffer.Write(payload)
			}
		case PacketTypePrngSeed:
			err := decoder.PrngRegen(payload)
			if err != nil {
				return err
			}
		default:
			// Ignore unknown packet types.
	}
	return nil
}

