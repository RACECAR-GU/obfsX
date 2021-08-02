package emily

import (
	"net"

	"github.com/google/uuid"
)

// NEXT: Share an account across multiple conns

type Conn struct {
	net.Conn

	uuid 	[16]byte

	// Email account stuff
	host		string
	smtpPort	uint64
	imapPort	uint64
	uname		string
	password	string

	rcvrs		[]string

	queue		[][]byte
	slots		[]slot
	sent		uint32
	rcvd		uint32
	
	frags		[]frag
	
	closed		bool
}

func NewConn(host string, smtpPort, imapPort uint64, uname, password string, rcvrs []string) (*Conn, error) {
	conn := new(Conn)
	conn.uuid = uuid.NewRandom()

	conn.host = host
	conn.smtpPort = smtpPort
	conn.imapPort = imapPort
	conn.uname = uname
	conn.password = password

	conn.rcvrs = rcvrs

	// TODO: Some index for the inbox, a client should start at the current inbox level. Server: think more

	return conn, nil
}

func (em *Conn) Write(b []byte) (n int, err error) {
	// NEXT: Combine messages to reduce deadweight
	sent := 0
	for sent != len(b) {
		if len(em.slots) == 0 {
			em.load_slots(10)
		}
		slot, em.slots := em.slots[0], em.slots[1:]
		for !slot.time.Before(time.Now()) {
			time.sleep(100 * time.Millisecond)
		}
		n, err := em.send(b, sent, slot)
		if err != nil {
			return 0, err
		}
		sent += n
	}
	return sent, nil
}

// NEXT: Add dummy traffic

func (em *Conn) Read(b []byte) (int, error) {
	// NEXT: Read until a message is complete
}
