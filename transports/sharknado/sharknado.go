package sharknado

import (
	"math/rand"
	"net"
	"time"

	"github.com/RACECAR-GU/obfsX.git/common/drbg"
	"github.com/RACECAR-GU/obfsX.git/common/log"
	erand "golang.org/x/exp/rand"
	"gonum.org/v1/gonum/stat/distuv"
)

const (
	// FIXME: These are arbitrary numbers, without any rationale behind them.
	minBreakAfterBytes  = 1500
	randBreakAfterBytes = 20 * 1500
	minNumDummyBytes    = 100
	randNumDummyBytes   = 10000

	// The maximum and minimum included number of seconds in between two
	// heartbeats.  Also arbitrary numbers.
	minHeartbeatInterval = 5
	maxHeartbeatInterval = 60 * 5

	// Start a heartbeat with probability 1/heartbeatDenominator.  Also an
	// arbitrary number.
	heartbeatDenominator = 2
)

// DummyTrafficFunc must be implemented by transports that want to use
// sharknado.  The function takes as input the number of desired dummy traffic
// bytes and returns a []byte slice (and an error) that is ready to be written
// to the wire.  Needless to say, a transport must support dummy traffic to use
// sharknado.
type DummyTrafficFunc func(int) ([]byte, error)

// SharknadoConn implements the net.Conn interface.
type SharknadoConn struct {
	// Embed a net.Conn and inherit its members.
	net.Conn
	GetDummyTraffic DummyTrafficFunc

	breakAfterDist *distuv.Poisson
	numDummyDist   *distuv.Poisson

	breakAfter int
	bytesRcvd  int
}

// NewSharknadoConn creates a new Sharknado connection.
func NewSharknadoConn(conn net.Conn, getDummyTraffic DummyTrafficFunc, seed *drbg.Seed) *SharknadoConn {

	// Initialize the deterministic random number generator.
	log.Debugf("Using sharknado seed %x.", *seed)
	drbg, _ := drbg.NewHashDrbg(seed)
	rng := rand.New(drbg)

	// FIXME: Poisson wants an exp/rand type but obfs4 only implements a
	// math/rand type.
	breakAfterDist := &distuv.Poisson{float64(minBreakAfterBytes + rng.Intn(randBreakAfterBytes)), erand.NewSource(4)}
	numDummyDist := &distuv.Poisson{float64(minNumDummyBytes + rng.Intn(randNumDummyBytes)), erand.NewSource(4)}

	sc := &SharknadoConn{conn, getDummyTraffic, breakAfterDist, numDummyDist, int(breakAfterDist.Rand()), 0}

	// Decide if we should start a heartbeat.
	if rng.Intn(heartbeatDenominator) == 0 {
		log.Debugf("Starting heartbeat routine.")
		// Determine the interval in between heartbeats.
		r := rng.Intn(maxHeartbeatInterval + 1)
		if r < minHeartbeatInterval {
			r = minHeartbeatInterval
		}
		go sc.heartbeat(r)
	}

	return sc
}

// resetState resets our two state variables; `breakAfter` by assigning it a
// new random value, and `bytesRcvd` by resetting it to 0.
func (sn *SharknadoConn) resetState() {

	sn.breakAfter = int(sn.breakAfterDist.Rand())
	sn.bytesRcvd = 0
	log.Debugf("Reset state. Will send dummy traffic again after %d incoming bytes.", sn.breakAfter)
}

// shouldBreakBurst returns `true` if we should break the current burst of
// incoming packets and `false` otherwise.
func (sn *SharknadoConn) shouldBreakBurst() bool {

	return sn.bytesRcvd > sn.breakAfter
}

// sendDummyTraffic sends dummy traffic and returns the result of the Write()
// call.
func (sn *SharknadoConn) sendDummyTraffic() (int, error) {

	numBytes := int(sn.numDummyDist.Rand())
	log.Debugf("Breaking burst with %d bytes of dummy traffic.", numBytes)
	data, err := sn.GetDummyTraffic(numBytes)
	if err != nil {
		return 0, err
	}
	return sn.Conn.Write(data)
}

// heartbeat implements a heartbeat mechanism that sends dummy traffic every
func (sn *SharknadoConn) heartbeat(interval int) {

	duration := time.Second * time.Duration(interval)
	numBytes := int(sn.numDummyDist.Rand())
	log.Debugf("Sending %d bytes of heartbeat dummy traffic.", numBytes)
	for {
		time.Sleep(duration)
		if sn.GetDummyTraffic != nil { // IDEA: Intuitively, I feel like this could be fixed...
																	// e.g. perhaps make "established" a more universal var for conns...
			data, err := sn.GetDummyTraffic(numBytes)
			if err != nil {
				log.Debugf("Error while getting dummy traffic.")
				continue
			}
			log.Debugf("Sending %d bytes of heartbeat data.", len(data))
			_, err = sn.Conn.Write(data)
			if err != nil {
				log.Debugf("Error while writing. Stopping heartbeat.")
				return
			}
		}
	}
}

func (sn *SharknadoConn) Write(b []byte) (int, error) {

	n, err := sn.Conn.Write(b)
	// log.Debugf("Sharknado: %d ->", n)
	return n, err
}

func (sn *SharknadoConn) Read(b []byte) (int, error) {

	n, err := sn.Conn.Read(b)
	sn.bytesRcvd += n
	// log.Debugf("Sharknado: <- %d", n)

	if sn.shouldBreakBurst() {
		if _, err2 := sn.sendDummyTraffic(); err2 != nil {
			log.Debugf("Failed to send dummy traffic: %s", err2)
		}
		sn.resetState()
	}

	return n, err
}
