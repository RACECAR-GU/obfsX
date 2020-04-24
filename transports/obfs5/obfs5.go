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

// Package obfs5 provides an implementation of the Tor Project's obfs5
// obfuscation protocol.
package obfs5 // import "gitlab.com/yawning/obfs5.git/transports/obfs5"

// TODO: Cut this code base down significantly - go through OBFS4 code and remove duplicity
// Potential approach - spin up an obfs4conn and wrap w/ riverrun and sharknado

import (
	"bytes"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"strconv"
	"syscall"
	"time"

	"git.torproject.org/pluggable-transports/goptlib.git"
	"gitlab.com/yawning/obfs4.git/common/drbg"
	"gitlab.com/yawning/obfs4.git/common/log"
	"gitlab.com/yawning/obfs4.git/common/ntor"
	"gitlab.com/yawning/obfs4.git/common/probdist"
	"gitlab.com/yawning/obfs4.git/common/replayfilter"
	"gitlab.com/yawning/obfs4.git/transports/base"
	"gitlab.com/yawning/obfs4.git/transports/obfs4/framing"
	"gitlab.com/yawning/obfs4.git/transports/obfs4"
	"gitlab.com/yawning/obfs4.git/transports/sharknado"
	"gitlab.com/yawning/obfs4.git/transports/riverrun"
	f "gitlab.com/yawning/obfs4.git/common/framing"
)

const (
	transportName = "obfs5"

	nodeIDArg     = "node-id"
	publicKeyArg  = "public-key"
	privateKeyArg = "private-key"
	seedArg       = "drbg-seed"
	iatArg        = "iat-mode"
	certArg       = "cert"

	biasCmdArg = "obfs5-distBias"

	seedLength             = drbg.SeedLength
	headerLength           = framing.FrameOverhead + obfs4.PacketOverhead
	clientHandshakeTimeout = time.Duration(60) * time.Second
	serverHandshakeTimeout = time.Duration(30) * time.Second
	replayTTL              = time.Duration(3) * time.Hour

	maxIATDelay   = 100
	maxCloseDelay = 60
)

const (
	iatNone = iota
	iatEnabled
	iatParanoid
)

// biasedDist controls if the probability table will be ScrambleSuit style or
// uniformly distributed.
var biasedDist bool

type obfs5ClientArgs struct {
	nodeID     *ntor.NodeID
	publicKey  *ntor.PublicKey
	sessionKey *ntor.Keypair
	iatMode    int
}

// Transport is the obfs5 implementation of the base.Transport interface.
type Transport struct{}

// Name returns the name of the obfs5 transport protocol.
func (t *Transport) Name() string {
	return transportName
}

// ClientFactory returns a new obfs5ClientFactory instance.
func (t *Transport) ClientFactory(stateDir string) (base.ClientFactory, error) {
	cf := &obfs5ClientFactory{transport: t}
	return cf, nil
}

// ServerFactory returns a new obfs5ServerFactory instance.
func (t *Transport) ServerFactory(stateDir string, args *pt.Args) (base.ServerFactory, error) {
	st, err := serverStateFromArgs(stateDir, args)
	if err != nil {
		return nil, err
	}

	var iatSeed *drbg.Seed
	if st.iatMode != iatNone {
		iatSeedSrc := sha256.Sum256(st.drbgSeed.Bytes()[:])
		var err error
		iatSeed, err = drbg.SeedFromBytes(iatSeedSrc[:])
		if err != nil {
			return nil, err
		}
	}

	// Store the arguments that should appear in our descriptor for the clients.
	ptArgs := pt.Args{}
	ptArgs.Add(certArg, st.cert.String())
	ptArgs.Add(iatArg, strconv.Itoa(st.iatMode))

	// Initialize the replay filter.
	filter, err := replayfilter.New(replayTTL)
	if err != nil {
		return nil, err
	}

	// Initialize the close thresholds for failed connections.
	drbg, err := drbg.NewHashDrbg(st.drbgSeed)
	if err != nil {
		return nil, err
	}
	rng := rand.New(drbg)

	sf := &obfs4ServerFactory{t, &ptArgs, st.nodeID, st.identityKey, st.drbgSeed, iatSeed, st.iatMode, filter, rng.Intn(maxCloseDelay)}
	return sf, nil
}

type obfs5ClientFactory struct {
	transport base.Transport
}

func (cf *obfs5ClientFactory) Transport() base.Transport {
	return cf.transport
}

func (cf *obfs5ClientFactory) ParseArgs(args *pt.Args) (interface{}, error) {
	nodeID, publicKey, err := obfs4.ParseCert(args)
	if err != nil {
		return nil, err
	}

	// IAT config is common across the two bridge line formats.
	iatStr, ok := args.Get(iatArg)
	if !ok {
		return nil, fmt.Errorf("missing argument '%s'", iatArg)
	}
	iatMode, err := strconv.Atoi(iatStr)
	if err != nil || iatMode < iatNone || iatMode > iatParanoid {
		return nil, fmt.Errorf("invalid iat-mode '%d'", iatMode)
	}

	// Generate the session key pair before connectiong to hide the Elligator2
	// rejection sampling from network observers.
	sessionKey, err := ntor.NewKeypair(true)
	if err != nil {
		return nil, err
	}

	return &obfs5ClientArgs{nodeID, publicKey, sessionKey, iatMode}, nil
}

func (cf *obfs5ClientFactory) Dial(network, addr string, dialFn base.DialFunc, args interface{}) (net.Conn, error) {
	// Validate args before bothering to open connection.
	ca, ok := args.(*obfs5ClientArgs)
	if !ok {
		return nil, fmt.Errorf("invalid argument type for args")
	}
	conn, err := dialFn(network, addr)
	if err != nil {
		return nil, err
	}
	dialConn := conn
	if conn, err = newObfs5ClientConn(conn, ca); err != nil {
		dialConn.Close()
		return nil, err
	}
	return conn, nil
}

type obfs5ServerFactory struct {
	transport base.Transport
	args      *pt.Args

	nodeID       *ntor.NodeID
	identityKey  *ntor.Keypair
	lenSeed      *drbg.Seed
	iatSeed      *drbg.Seed
	iatMode      int
	replayFilter *replayfilter.ReplayFilter

	closeDelay int
}

func (sf *obfs5ServerFactory) Transport() base.Transport {
	return sf.transport
}

func (sf *obfs5ServerFactory) Args() *pt.Args {
	return sf.args
}

func (sf *obfs5ServerFactory) WrapConn(conn net.Conn) (net.Conn, error) {
	// Not much point in having a separate newObfs5ServerConn routine when
	// wrapping requires using values from the factory instance.

	// Generate the session keypair *before* consuming data from the peer, to
	// attempt to mask the rejection sampling due to use of Elligator2.  This
	// might be futile, but the timing differential isn't very large on modern
	// hardware, and there are far easier statistical attacks that can be
	// mounted as a distinguisher.
	sessionKey, err := ntor.NewKeypair(true)
	if err != nil {
		return nil, err
	}

	lenDist := probdist.New(sf.lenSeed, 0, f.MaximumSegmentLength, biasedDist)
	var iatDist *probdist.WeightedDist
	if sf.iatSeed != nil {
		iatDist = probdist.New(sf.iatSeed, 0, maxIATDelay, biasedDist)
	}

	_, publicKey, err := obfs4.ParseCert(sf.args)
	if err != nil {
		return nil, err
	}
	serverSeed, err := drbg.SeedFromBytes(publicKey[:drbg.SeedLength])
	if err != nil {
		return nil, err
	}
	c := &obfs5Conn{conn, true, lenDist, iatDist, sf.iatMode, nil, nil, false}
	c.Conn, err = riverrun.NewRiverrunConn(c.Conn, c.isServer, serverSeed)
	if err != nil {
		return nil, err
	}

	startTime := time.Now()

	if err = c.serverHandshake(sf, sessionKey); err != nil {
		c.closeAfterDelay(sf, startTime)
		return nil, err
	}

	return c, nil
}

type obfs5Conn struct {
	net.Conn

	isServer bool

	lenDist *probdist.WeightedDist
	iatDist *probdist.WeightedDist
	iatMode int

	encoder *framing.ObfsEncoder
	decoder *framing.ObfsDecoder

	connEstablished bool
}

func newObfs5ClientConn(conn net.Conn, args *obfs5ClientArgs) (c *obfs5Conn, err error) {
	// Generate the initial protocol polymorphism distribution(s).
	var seed *drbg.Seed
	if seed, err = drbg.NewSeed(); err != nil {
		return
	}
	lenDist := probdist.New(seed, 0, f.MaximumSegmentLength, biasedDist)
	var iatDist *probdist.WeightedDist
	if args.iatMode != iatNone {
		var iatSeed *drbg.Seed
		iatSeedSrc := sha256.Sum256(seed.Bytes()[:])
		if iatSeed, err = drbg.SeedFromBytes(iatSeedSrc[:]); err != nil {
			return
		}
		iatDist = probdist.New(iatSeed, 0, maxIATDelay, biasedDist)
	}
	// All clients that talk to the same obfs5 server should shape their flows
	// identically, so we derive riverrun/sharknado's seed from our obfs5 server's
	// public key.
	serverSeed, err := drbg.SeedFromBytes(args.publicKey[:drbg.SeedLength])
	if err != nil {
		return nil, err
	}

	// Allocate the client structure.
	c = &obfs5Conn{conn, false, lenDist, iatDist, args.iatMode, nil, nil, false}
	c.Conn, err = riverrun.NewRiverrunConn(c.Conn, c.isServer, serverSeed)
	if err != nil {
		return nil, err
	}
	c.Conn = sharknado.NewSharknadoConn(c.Conn, c.getDummyTraffic, serverSeed)

	// Start the handshake timeout.
	deadline := time.Now().Add(clientHandshakeTimeout)
	if err = conn.SetDeadline(deadline); err != nil {
		return nil, err
	}

	if err = c.clientHandshake(args.nodeID, args.publicKey, args.sessionKey); err != nil {
		return nil, err
	}

	// Stop the handshake timeout.
	if err = conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}

	return
}

func (conn *obfs5Conn) clientHandshake(nodeID *ntor.NodeID, peerIdentityKey *ntor.PublicKey, sessionKey *ntor.Keypair) error {
	if conn.isServer {
		return fmt.Errorf("clientHandshake called on server connection")
	}

	// Generate and send the client handshake.
	hs := newClientHandshake(nodeID, peerIdentityKey, sessionKey)
	blob, err := hs.generateHandshake()
	if err != nil {
		return err
	}
	if _, err = conn.Conn.Write(blob); err != nil {
		return err
	}

	// Consume the server handshake.
	var hsBuf [maxHandshakeLength]byte
	receiveBuffer := bytes.NewBuffer(nil)
	for {
		n, err := conn.Conn.Read(hsBuf[:])
		if err != nil {
			// The Read() could have returned data and an error, but there is
			// no point in continuing on an EOF or whatever.
			return err
		}
		receiveBuffer.Write(hsBuf[:n])

		n, seed, err := hs.parseServerHandshake(receiveBuffer.Bytes())
		if err == ErrMarkNotFoundYet {
			continue
		} else if err != nil {
			return err
		}
		_ = receiveBuffer.Next(n)

		// Use the derived key material to intialize the link crypto.
		okm := ntor.Kdf(seed, framing.KeyLength*2)
		conn.encoder = newEncoder(okm[:framing.KeyLength])
		conn.newDecoder(okm[framing.KeyLength:])
		conn.decoder.ReceiveBuffer = receiveBuffer
		conn.connEstablished = true

		return nil
	}
}

func newEncoder(key []byte) *framing.ObfsEncoder {
	encoder := framing.NewObfsEncoder(key)
	encoder.ChopPayload = obfs4.MakeUnpaddedPayload
	encoder.MaxPacketPayloadLength = obfs4.MaxPacketPayloadLength
	return encoder
}

func (conn *obfs5Conn) newDecoder(key []byte) {
	decoder := framing.NewObfsDecoder(key)
	decoder.PrngRegen = conn.prngRegen
	conn.decoder = decoder
}

func (conn *obfs5Conn) serverHandshake(sf *obfs5ServerFactory, sessionKey *ntor.Keypair) error {
	if !conn.isServer {
		return fmt.Errorf("serverHandshake called on client connection")
	}

	// Generate the server handshake, and arm the base timeout.
	hs := newServerHandshake(sf.nodeID, sf.identityKey, sessionKey)
	if err := conn.Conn.SetDeadline(time.Now().Add(serverHandshakeTimeout)); err != nil {
		return err
	}

	// Consume the client handshake.
	var hsBuf [maxHandshakeLength]byte
	receiveBuffer := bytes.NewBuffer(nil)
	for {
		n, err := conn.Conn.Read(hsBuf[:])
		if err != nil {
			// The Read() could have returned data and an error, but there is
			// no point in continuing on an EOF or whatever.
			return err
		}
		receiveBuffer.Write(hsBuf[:n])

		seed, err := hs.parseClientHandshake(sf.replayFilter, receiveBuffer.Bytes())
		if err == ErrMarkNotFoundYet {
			continue
		} else if err != nil {
			return err
		}
		receiveBuffer.Reset()

		if err := conn.Conn.SetDeadline(time.Time{}); err != nil {
			return nil
		}

		// Use the derived key material to intialize the link crypto.
		okm := ntor.Kdf(seed, framing.KeyLength*2)
		conn.encoder = newEncoder(okm[framing.KeyLength:])
		conn.decoder = framing.NewObfsDecoder(okm[:framing.KeyLength])

		break
	}

	// Since the current and only implementation always sends a PRNG seed for
	// the length obfuscation, this makes the amount of data received from the
	// server inconsistent with the length sent from the client.
	//
	// Rebalance this by tweaking the client mimimum padding/server maximum
	// padding, and sending the PRNG seed unpadded (As in, treat the PRNG seed
	// as part of the server response).  See inlineSeedFrameLength in
	// handshake_ntor.go.

	// Generate/send the response.
	blob, err := hs.generateHandshake()
	if err != nil {
		return err
	}
	var frameBuf bytes.Buffer
	if _, err = frameBuf.Write(blob); err != nil {
		return err
	}

	// Send the PRNG seed as the first packet.
	if err := conn.encoder.MakePacket(&frameBuf, obfs4.MakePayload(framing.PacketTypePrngSeed, sf.lenSeed.Bytes()[:], 0)); err != nil {
		return err
	}
	if _, err = conn.Conn.Write(frameBuf.Bytes()); err != nil {
		return err
	}
	conn.connEstablished = true

	return nil
}

func (conn *obfs5Conn) Read(b []byte) (n int, err error) {
	return conn.decoder.Read(b, conn.Conn)
}
func (conn *obfs5Conn) prngRegen(payload []byte) error {
	// Only regenerate the distribution if we are the client.
	if len(payload) == obfs4.SeedPacketPayloadLength && conn.isServer {
		seed, err := drbg.SeedFromBytes(payload)
		if err != nil {
			return err
		}
		conn.lenDist.Reset(seed)
		if conn.iatDist != nil {
			iatSeedSrc := sha256.Sum256(seed.Bytes()[:])
			iatSeed, err := drbg.SeedFromBytes(iatSeedSrc[:])
			if err != nil {
				return err
			}
			conn.iatDist.Reset(iatSeed)
		}
	}
	return nil
}

func (conn *obfs5Conn) Write(b []byte) (n int, err error) {
	var frameBuf bytes.Buffer
	frameBuf, n, err = conn.encoder.Chop(b, framing.PacketTypePayload)
	if err != nil {
		return
	}

	if conn.iatMode != iatParanoid {
		// For non-paranoid IAT, pad once per burst.  Paranoid IAT handles
		// things differently.
		if err = conn.padBurst(&frameBuf, conn.lenDist.Sample()); err != nil {
			return 0, err
		}
	}

	// Write the pending data onto the network.  Partial writes are fatal,
	// because the frame encoder state is advanced, and the code doesn't keep
	// frameBuf around.  In theory, write timeouts and whatnot could be
	// supported if this wasn't the case, but that complicates the code.
	if conn.iatMode != iatNone {
		var iatFrame [f.MaximumSegmentLength]byte
		for frameBuf.Len() > 0 {
			iatWrLen := 0

			switch conn.iatMode {
			case iatEnabled:
				// Standard (ScrambleSuit-style) IAT obfuscation optimizes for
				// bulk transport and will write ~MTU sized frames when
				// possible.
				iatWrLen, err = frameBuf.Read(iatFrame[:])

			case iatParanoid:
				// Paranoid IAT obfuscation throws performance out of the
				// window and will sample the length distribution every time a
				// write is scheduled.
				targetLen := conn.lenDist.Sample()
				if frameBuf.Len() < targetLen {
					// There's not enough data buffered for the target write,
					// so padding must be inserted.
					if err = conn.padBurst(&frameBuf, targetLen); err != nil {
						return 0, err
					}
					if frameBuf.Len() != targetLen {
						// Ugh, padding came out to a value that required more
						// than one frame, this is relatively unlikely so just
						// resample since there's enough data to ensure that
						// the next sample will be written.
						continue
					}
				}
				iatWrLen, err = frameBuf.Read(iatFrame[:targetLen])
			}
			if err != nil {
				return 0, err
			} else if iatWrLen == 0 {
				panic(fmt.Sprintf("BUG: Write(), iat length was 0"))
			}

			// Calculate the delay.  The delay resolution is 100 usec, leading
			// to a maximum delay of 10 msec.
			iatDelta := time.Duration(conn.iatDist.Sample() * 100)

			// Write then sleep.
			_, err = conn.Conn.Write(iatFrame[:iatWrLen])
			if err != nil {
				return 0, err
			}
			time.Sleep(iatDelta * time.Microsecond)
		}
	} else {
		_, err = conn.Conn.Write(frameBuf.Bytes())
	}

	return
}

func (conn *obfs5Conn) SetDeadline(t time.Time) error {
	return syscall.ENOTSUP
}

func (conn *obfs5Conn) SetWriteDeadline(t time.Time) error {
	return syscall.ENOTSUP
}

func (conn *obfs5Conn) closeAfterDelay(sf *obfs5ServerFactory, startTime time.Time) {
	// I-it's not like I w-wanna handshake with you or anything.  B-b-baka!
	defer conn.Conn.Close()

	delay := time.Duration(sf.closeDelay)*time.Second + serverHandshakeTimeout
	deadline := startTime.Add(delay)
	if time.Now().After(deadline) {
		return
	}

	if err := conn.Conn.SetReadDeadline(deadline); err != nil {
		return
	}

	// Consume and discard data on this connection until the specified interval
	// passes.
	_, _ = io.Copy(ioutil.Discard, conn.Conn)
}

func (conn *obfs5Conn) padBurst(burst *bytes.Buffer, toPadTo int) (err error) {
	tailLen := burst.Len() % f.MaximumSegmentLength

	padLen := 0
	if toPadTo >= tailLen {
		padLen = toPadTo - tailLen
	} else {
		padLen = (f.MaximumSegmentLength - tailLen) + toPadTo
	}

	if padLen > headerLength {
		err = conn.encoder.MakePacket(burst, obfs4.MakePayload(framing.PacketTypePayload, []byte{}, uint16(padLen-headerLength)))
		if err != nil {
			return
		}
	} else if padLen > 0 {
		err = conn.encoder.MakePacket(burst, obfs4.MakePayload(framing.PacketTypePayload, []byte{}, uint16(conn.encoder.MaxPacketPayloadLength)))
		if err != nil {
			return
		}
		err = conn.encoder.MakePacket(burst, obfs4.MakePayload(framing.PacketTypePayload, []byte{}, uint16(padLen)))
		if err != nil {
			return
		}
	}

	return
}

// getDummyTraffic must be of type sharknado.DummyTrafficFunc and return `n`
// bytes of dummy traffic that's ready to be written to the wire.
func (conn *obfs5Conn) getDummyTraffic(n int) ([]byte, error) {

	// We're still busy with the handshake and haven't determined our shared
	// secret yet.  We therefore cannot send dummy traffic just yet.
	if !conn.connEstablished {
		return nil, fmt.Errorf("Connection not yet established.  No dummy traffic available.")
	}

	var overhead = framing.FrameOverhead + conn.encoder.PacketOverhead
	var frameBuf bytes.Buffer
	for n > conn.encoder.MaxPacketPayloadLength {
		err := conn.encoder.MakePacket(&frameBuf, obfs4.MakePayload(framing.PacketTypePayload, nil, uint16(conn.encoder.MaxPacketPayloadLength)))
		if err != nil {
			return nil, err
		}
		n -= conn.encoder.MaxPacketPayloadLength + overhead
	}
	// Do we have enough remaining padding to fit it into a new frame?  If not,
	// let's just create an empty frame.
	if n < overhead {
		log.Debugf("Remaining n < frame overhead.")
		n = overhead
	}
	err := conn.encoder.MakePacket(&frameBuf, obfs4.MakePayload(framing.PacketTypePayload, nil, uint16(n-overhead)))
	if err != nil {
		return nil, err
	}
	log.Debugf("Size of dummy traffic buffer: %d", frameBuf.Len())
	return frameBuf.Bytes(), nil
}

func init() {
	flag.BoolVar(&biasedDist, biasCmdArg, false, "Enable obfs5 using ScrambleSuit style table generation")
}

var _ base.ClientFactory = (*obfs5ClientFactory)(nil)
var _ base.ServerFactory = (*obfs5ServerFactory)(nil)
var _ base.Transport = (*Transport)(nil)
var _ net.Conn = (*obfs4Conn)(nil)
