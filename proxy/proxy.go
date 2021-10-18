package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"sync"

	"git.torproject.org/pluggable-transports/snowflake.git/common/safelog"
	"git.torproject.org/pluggable-transports/snowflake.git/common/websocketconn"
	"github.com/gorilla/websocket"
)

const defaultRelayURL = "wss://snowflake.bamsoftware.com/"

var relayURL string
var sf base.ServerFactory

func CopyLoop(c1 io.ReadWriteCloser, c2 io.ReadWriteCloser) {
	var wg sync.WaitGroup
	copyer := func(dst io.ReadWriteCloser, src io.ReadWriteCloser) {
		defer wg.Done()
		// Ignore io.ErrClosedPipe because it is likely caused by the
		// termination of copyer in the other direction.
		if _, err := io.Copy(dst, src); err != nil && err != io.ErrClosedPipe {
			log.Printf("io.Copy inside CopyLoop generated an error: %v", err)
		}
		dst.Close()
		src.Close()
	}
	wg.Add(2)
	go copyer(c1, c2)
	go copyer(c2, c1)
	wg.Wait()
}

// We pass conn.RemoteAddr() as an additional parameter, rather than calling
// conn.RemoteAddr() inside this function, as a workaround for a hang that
// otherwise occurs inside of conn.pc.RemoteDescription() (called by
// RemoteAddr). https://bugs.torproject.org/18628#comment:8
func datachannelHandler(conn *net.Conn, remoteAddr net.Addr) {
	defer conn.Close()

	u, err := url.Parse(relayURL)
	if err != nil {
		log.Fatalf("invalid relay url: %s", err)
	}

	if remoteAddr != nil {
		// Encode client IP address in relay URL
		// XXX: Could this expose IPs to a malicious user?
		q := u.Query()
		clientIP := remoteAddr.String()
		q.Set("client_ip", clientIP)
		u.RawQuery = q.Encode()
	} else {
		log.Printf("no remote address given in websocket")
	}

	ws, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		log.Printf("error dialing relay: %s", err)
		return
	}
	wsConn := websocketconn.New(ws)
	log.Printf("connected to relay")
	defer wsConn.Close()
	CopyLoop(conn, wsConn)
	log.Printf("datachannelHandler ends")
}

func sf_setup() {
	// Setting necessary ENV variables NEXT: Could remove these? (they're in goptlib)
	os.Setenv("TOR_PT_MANAGED_TRANSPORT_VER", "1")
	os.Setenv("TOR_PT_SERVER_TRANSPORTS", "obfs5")
	os.Setenv("TOR_PT_STATE_LOCATION", "/log/obfs5")
	os.Setenv("TOR_PT_ORPORT", "127.0.0.1:0000")
	os.Setenv("TOR_PT_SERVER_BINDADDR", "obfs5-0.0.0.0:0000")

	if err := transports.Init(); err != nil {
		log.Fatalf(err)
	}

	ptServerInfo, err := pt.ServerSetup(transports.Transports())
	if err != nil {
		log.Fatalf(err)
	}

	var stateDir string

	if stateDir, err = pt.MakeStateDir(); err != nil {
		log.Fatalf("[ERROR]: No state directory: %s", err)
	}

	for _, bindaddr := range ptServerInfo.Bindaddrs {
		name := bindaddr.MethodName
		t := transports.Get(name)
		if t == nil {
			_ = pt.SmethodError(name, "no such transport is supported")
			continue
		}

		f, err := t.ServerFactory(stateDir, &bindaddr.Options)
		if err != nil {
			_ = pt.SmethodError(name, err.Error())
			continue
		}
		if sf != nil {
			log.Errf("Too many pts initialized.")
		}
		sf = f
	}
}

func main() {
	var logFilename string
	var unsafeLogging bool
	var keepLocalAddresses bool
	var port int

	flag.StringVar(&relayURL, "relay", defaultRelayURL, "websocket relay URL")
	flag.StringVar(&logFilename, "log", "", "log filename")
	flag.BoolVar(&unsafeLogging, "unsafe-logging", false, "prevent logs from being scrubbed")
	flag.BoolVar(&keepLocalAddresses, "keep-local-addresses", false, "keep local LAN address ICE candidates")
	flag.IntVar(&port, "port", 6666, "listening port")
	flag.Parse()

	var logOutput io.Writer = os.Stderr
	log.SetFlags(log.LstdFlags | log.LUTC)
	if logFilename != "" {
		f, err := os.OpenFile(logFilename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		logOutput = io.MultiWriter(os.Stderr, f)
	}
	if unsafeLogging {
		log.SetOutput(logOutput)
	} else {
		// We want to send the log output through our scrubber first
		log.SetOutput(&safelog.LogScrubber{Output: logOutput})
	}

	log.Println("starting")

	_, err = url.Parse(relayURL)
	if err != nil {
		log.Fatalf("invalid relay url: %s", err)
	}

	l, err := net.Listen("tcp", fmt.Sprintf(":%v", port)) // NEXT: Set the host?
	if err != nil {
		log.Fatalf("Failed listening: %s", err)
	}
	defer l.Close()

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Infof("Error accepting: ", err.Error())
			continue
		}

		// Instantiate the server transport method and handshake.
		remote, err := sf.WrapConn(conn)
		if err != nil {
			log.Warningf("handshake failed")
			continue
		}

		go dataChannelHandler(remote, nil) // NEXT: replace nil with proper thing
	}
}
