package tt

import (
	"fmt"
	"net"

	"github.com/RACECAR-GU/obfsX/transports/base"

	"git.torproject.org/pluggable-transports/goptlib.git"

	"github.com/xtaci/smux"
)

const (
	transportName = "turbotunnel"
)

type TTConn struct {
	*smux.Stream
	sess	*smux.Session
	pconn	net.PacketConn
}

func (conn *TTConn) Close() error {
	log.Infof("tt: closing stream %v", conn.ID())
	conn.Stream.Close()
	log.Infof("tt: closing underlying connections")
	// TODO: Close underlying conn(s)
	conn.pconn.Close()
	log.Printf("tt: discarding finished session")
	conn.sess.Close()
	return nil //TODO: return errors if any of the above do
}

type Transport struct {}
func (t *Transport) Name() string {
	return transportName
}

func (t *Transport) ClientFactory(stateDir string) (base.ClientFactory, error) {
	// TODO
}
type ClientFactory struct {
	transport base.Transport
}
func (cf *ClientFactory) Transport() base.Transport {
	return cf.transport
}

func (cf *ClientFactory) ParseArgs(args *pt.Args) (interface{}, error) {
	// TODO
}

// TODO: Deprecate dial, make a newClientConn. Refer to rr.
func (cf *ClientFactory) Dial(network, address string, dialer net.Dialer, args interface{}) (net.Conn, error) {
	// Cleanup functions to run before returning, in case of an error.
	var cleanup []func()
	defer func() {
		// Run cleanup in reverse order, as defer does.
		for i := len(cleanup) - 1; i >= 0; i-- {
			cleanup[i]()
		}
	}()

	// TODO: Get the underlying conns

	// Create a new smux session
	log.Printf("tt: starting a new session ---")
	pconn, sess, err := newSession(snowflakes)
	if err != nil {
		return nil, err
	}
	cleanup = append(cleanup, func() {
		pconn.Close()
		sess.Close()
	})

	stream, err := sess.OpenStream()
	if err != nil {
		return nil, err
	}
	log.Infof("TT: Begginning stream %v", stream.ID())
	cleanup = append(cleanup, func() { stream.Close() })

	// All good, clear the cleanup list.
	cleanup = nil
	return &TTConn{Stream: stream, sess: sess, pconn: pconn}
}

func (t *Transport) ProxyFactory(stateDir string, args *pt.Args) (base.ProxyFactory, error) {
	return nil, fmt.Errorf("tt: Proxy factory is not implemented")
	// TODO: This should just do nothing?
}
