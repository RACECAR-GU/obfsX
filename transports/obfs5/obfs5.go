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

import (
	"flag"
	"fmt"
	"net"

	"git.torproject.org/pluggable-transports/goptlib.git"
	"gitlab.com/yawning/obfs4.git/common/drbg"
	"gitlab.com/yawning/obfs4.git/transports/base"
	"gitlab.com/yawning/obfs4.git/transports/obfs4"
	//"gitlab.com/yawning/obfs4.git/transports/sharknado"
	"gitlab.com/yawning/obfs4.git/transports/riverrun"
)

const (
	transportName = "obfs5"

	biasCmdArg = "obfs5-distBias"
)

// biasedDist controls if the probability table will be ScrambleSuit style or
// uniformly distributed.
var biasedDist bool

type ClientArgs struct {
	*obfs4.ClientArgs
}

// Transport is the obfs5 implementation of the base.Transport interface.
type Transport struct{
	*obfs4.Transport
}

// Name returns the name of the obfs5 transport protocol.
func (t *Transport) Name() string {
	return transportName
}

// ClientFactory returns a new ClientFactory instance.
func (t *Transport) ClientFactory(stateDir string) (base.ClientFactory, error) {
	cf := new(ClientFactory)
	cf.ClientFactory = &obfs4.ClientFactory{t}
	return cf, nil
}

// ServerFactory returns a new ServerFactory instance.
func (t *Transport) ServerFactory(stateDir string, args *pt.Args) (s base.ServerFactory, err error) {
	sf := new(ServerFactory)
	subsf, err := obfs4.NewServerFactory(t, stateDir, args)
	if err != nil {
		return nil, err
	}
	sf.ServerFactory = subsf

	return sf, nil
}

type ClientFactory struct {
	*obfs4.ClientFactory
}

func (cf *ClientFactory) Dial(network, addr string, dialFn base.DialFunc, args interface{}) (net.Conn, error) {
	// Validate args before bothering to open connection.
	ca := new(ClientArgs)
	subca, ok := args.(*obfs4.ClientArgs)
	if !ok {
		return nil, fmt.Errorf("invalid argument type for args")
	}
	ca.ClientArgs = subca
	conn, err := dialFn(network, addr)
	if err != nil {
		return nil, err
	}
	dialConn := conn
	if conn, err = NewClientConn(conn, ca); err != nil {
		dialConn.Close()
		return nil, err
	}
	return conn, nil
}

type ServerFactory struct {
	*obfs4.ServerFactory
}

func (sf *ServerFactory) WrapConn(conn net.Conn) (net.Conn, error) {
	// Not much point in having a separate newServerConn routine when
	// wrapping requires using values from the factory instance.

	_, publicKey, err := obfs4.ParseCert(sf.Args())
	if err != nil {
		return nil, err
	}
	serverSeed, err := drbg.SeedFromBytes(publicKey[:drbg.SeedLength])
	if err != nil {
		return nil, err
	}
	inner, err := riverrun.NewRiverrunConn(conn, true, serverSeed)
	if err != nil {
		return nil, err
	}

	return sf.ServerFactory.WrapConn(inner)
}

type Conn struct {
	*obfs4.Conn
}

func NewClientConn(conn net.Conn, args *ClientArgs) (c *Conn, err error) {
	// All clients that talk to the same obfs5 server should shape their flows
	// identically, so we derive riverrun/sharknado's seed from our obfs5 server's
	// public key.
	serverSeed, err := drbg.SeedFromBytes(args.PublicKey[:drbg.SeedLength])
	if err != nil {
		return nil, err
	}

	// Allocate the client structure.
	rr, err := riverrun.NewRiverrunConn(conn, false, serverSeed)
	if err != nil {
		return nil, err
	}
	outer, err := obfs4.NewClientConn(rr, args.ClientArgs)
	if err != nil {
		return nil, err
	}
	//outer.Conn = sharknado.NewSharknadoConn(rr, outer.GetDummyTraffic, serverSeed)

	c = new(Conn)
	c.Conn = outer
	return
}

func init() {
	flag.BoolVar(&biasedDist, biasCmdArg, false, "Enable obfs5 using ScrambleSuit style table generation")
}

var _ base.ClientFactory = (*ClientFactory)(nil)
var _ base.ServerFactory = (*ServerFactory)(nil)
var _ base.Transport = (*Transport)(nil)
var _ net.Conn = (*Conn)(nil)
