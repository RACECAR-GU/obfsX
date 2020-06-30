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

package obfs4

import (
	"encoding/binary"
	"fmt"

	"github.com/RACECAR-GU/obfsX/transports/obfs4/framing"
	f "github.com/RACECAR-GU/obfsX/common/framing"
)

const (
	PacketOverhead          = f.LengthLength + f.TypeLength
	MaxPacketPayloadLength  = framing.MaximumFramePayloadLength - PacketOverhead
	SeedPacketPayloadLength = seedLength
)

var zeroPadBytes [MaxPacketPayloadLength]byte

func MakeUnpaddedPayload(pktType uint8, data []byte) []byte {
	return MakePayload(pktType, data, 0)
}

func MakePayload(pktType uint8, data []byte, padLen uint16) []byte {

	if len(data)+int(padLen) > MaxPacketPayloadLength {
		panic(fmt.Sprintf("BUG: makePacyload() len(data) + padLen > MaxPacketPayloadLength: %d + %d > %d",
			len(data), padLen, MaxPacketPayloadLength))
	}

	// Payload is:
	//   uint8_t type      packetTypePayload (0x00)
	//   uint16_t length   Length of the payload (Big Endian).
	//   uint8_t[] payload Data payload.
	//   uint8_t[] padding Padding.
	payload := make([]byte, f.TypeLength + f.LengthLength + len(data) + int(padLen))
	payload[0] = pktType
	binary.BigEndian.PutUint16(payload[f.TypeLength:], uint16(len(data)))
	if len(data) > 0 {
		copy(payload[f.TypeLength+f.LengthLength:], data[:])
	}
	if padLen > 0 {
		copy(payload[f.TypeLength+f.LengthLength+len(data):], zeroPadBytes[:padLen])
	}
	return payload
}
