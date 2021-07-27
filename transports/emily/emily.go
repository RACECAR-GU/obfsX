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
package emily // import "github.com/RACECAR-GU/obfsX/transports/obfs5"

import (
	"flag"
	"fmt"
	"net"

	"git.torproject.org/pluggable-transports/goptlib.git"
	"github.com/RACECAR-GU/obfsX/common/drbg"
	"github.com/RACECAR-GU/obfsX/transports/base"
)

const (
	transportName = "emily" // EMail, I Love Ya
)

type ClientArgs struct {
	// TODO
}

// Implementation of the base.Transport interface.
type Transport struct{
	// TODO
}
// Name returns the name of the emily transport protocol.
func (t *Transport) Name() string {
	return transportName
}
// ClientFactory: See ./ClientFactory.go
// Serverfactory: See ./ServerFactory.go

type Conn struct {
	// TODO
}

func NewClientConn(conn net.Conn, args *ClientArgs) (c *Conn, err error) {
	// TODO
}

func init() {
}

var _ base.ClientFactory = (*ClientFactory)(nil)
var _ base.ServerFactory = (*ServerFactory)(nil)
var _ base.Transport = (*Transport)(nil)
var _ net.Conn = (*Conn)(nil)
