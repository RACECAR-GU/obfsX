package turbotunnel

import (
	"net"

	"git.torproject.org/pluggable-transports/snowflake.git/common/turbotunnel"

	snow "git.torproject.org/pluggable-transports/snowflake.git/client/lib"

	"github.com/xtaci/smux"

	"github.com/RACECAR-GU/obfsX/common/log"
)

type dummyAddr struct{}

func (addr dummyAddr) Network() string { return "dummy" }
func (addr dummyAddr) String() string  { return "dummy" }

// Implements the net.Conn interface
type Conn struct {
	*smux.Stream // This implements net.Conn
	sess	*smux.Session
	pconn	net.PacketConn
	mConns	*managedConns
}

// Similar to SnowflakeCollector, but lacking Collect
// Currently iterates through the full set of conns.
// More complex situations could be done later.
type managedConns struct {
	conns []net.Conn
	index uint
}
func newManagedConns(conns []net.Conn) *managedConns {
	mc := new(managedConns)
	mc.conns = conns
	return mc
}
func (mc *managedConns) pop() net.Conn {
	next := mc.index
	mc.index += 1
	return mc.conns[next % uint(len(mc.conns))]
}
func (mc *managedConns) Close() {
	// NEXT: Return err if it should
	for _, c := range mc.conns {
		c.Close()
	}
}

func (conn *Conn) Close() error {
	log.Infof("tt: closing stream %v", conn.ID())
	conn.Stream.Close()
	log.Infof("tt: closing underlying connections")
	conn.mConns.Close()
	conn.pconn.Close()
	log.Infof("tt: discarding finished session")
	conn.sess.Close()
	return nil //NEXT: return errors if any of the above do
}

func NewConn(conns []net.Conn) (*Conn, error) {
	// Cleanup functions to run before returning, in case of an error.
	var cleanup []func()
	defer func() {
		// Run cleanup in reverse order, as defer does.
		for i := len(cleanup) - 1; i >= 0; i-- {
			cleanup[i]()
		}
	}()

	mConns := newManagedConns(conns)
	cleanup = append(cleanup, func() {
		mConns.Close()
	})

	// Create a new smux session
	log.Infof("tt: starting a new session ---")
	pconn, sess, err := newSession(mConns)
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
	return &Conn{Stream: stream, sess: sess, pconn: pconn, mConns: mConns}, nil
}

// newSession returns a new smux.Session and the net.PacketConn it is running
// over. The net.PacketConn successively connects through Snowflake proxies
// pulled from snowflakes.
func newSession(conns *managedConns) (net.PacketConn, *smux.Session, error) {
	clientID := turbotunnel.NewClientID()

	// We build a persistent KCP session on a sequence of ephemeral WebRTC
	// connections. This dialContext tells RedialPacketConn how to get a new
	// WebRTC connection when the previous one dies. Inside each WebRTC
	// connection, we use EncapsulationPacketConn to encode packets into a
	// stream.
	dialContext := func(ctx context.Context) (net.PacketConn, error) {
		log.Infof("redialing on same connection")
		// Obtain an available WebRTC remote. May block.
		conn := conns.pop()
		if conn == nil {
			return nil, errors.New("handler: Received invalid conn")
		}
		log.Infof("Handler: conn assigned")
		// Send the magic Turbo Tunnel token.
		_, err := conn.Write(turbotunnel.Token[:])
		if err != nil {
			return nil, err
		}
		// Send ClientID prefix.
		_, err = conn.Write(clientID[:])
		if err != nil {
			return nil, err
		}
		return snow.NewEncapsulationPacketConn(dummyAddr{}, dummyAddr{}, conn), nil
	}
	pconn := turbotunnel.NewRedialPacketConn(dummyAddr{}, dummyAddr{}, dialContext)

	// conn is built on the underlying RedialPacketConn—when one WebRTC
	// connection dies, another one will be found to take its place. The
	// sequence of packets across multiple WebRTC connections drives the KCP
	// engine.
	conn, err := kcp.NewConn2(dummyAddr{}, nil, 0, 0, pconn)
	if err != nil {
		pconn.Close()
		return nil, nil, err
	}
	// Permit coalescing the payloads of consecutive sends.
	conn.SetStreamMode(true)
	// Set the maximum send and receive window sizes to a high number
	// Removes KCP bottlenecks: https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/-/issues/40026
	conn.SetWindowSize(65535, 65535)
	// Disable the dynamic congestion window (limit only by the
	// maximum of local and remote static windows).
	conn.SetNoDelay(
		0, // default nodelay
		0, // default interval
		0, // default resend
		1, // nc=1 => congestion window off
	)
	// On the KCP connection we overlay an smux session and stream.
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = 10 * time.Minute
	sess, err := smux.Client(conn, smuxConfig)
	if err != nil {
		conn.Close()
		pconn.Close()
		return nil, nil, err
	}

	return pconn, sess, err
}


