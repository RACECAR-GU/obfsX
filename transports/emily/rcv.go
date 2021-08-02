package emily

import (
	"bytes"
	"errors"
)

var ErrID = errors.New("rcv: Wrong conn id")

type frag struct {
	content	[]byte
	index	uint32

	last	bool
}

// rcv helpers
// ADDTEST
func (em *Conn) decode(b []byte) (frag, error) {
	buf := bytes.NewReader(b)

	var msg frag

	// stream id
	var uuid [16]byte
	err := binary.read(buf, binary.LittleEndian, &uuid)
	if err != nil {
		return nil, 0, false, err
	}
	if uuid != em.uuid {
		return nil, 0, false, ErrID
	}

	// message number
	var rcv_i uint32
	err := binary.read(buf, binary.LittleEndian, &rcv_i)
	if err != nil {
		return nil, 0, false, err
	}
	msg.index = rcv_i

	// controls
	var ctrl uint8
	err := binary.read(buf, binary.LittleEndian, &ctrl)
	if err != nil {
		return nil, 0, false, err
	}
	if ctrl % 2 == 1 {
		msg.last = true
	}

	// content length
	var size uint32
	err := binary.read(buf, binary.LittleEndian, &size)
	if err != nil {
		return nil, 0, false, err
	}

	msg.content = make([]byte, size)
	_, err := buf.read(msg.content)
	if err != nil {
		return nil, 0, false, err
	}

	return msg, nil

}

func (em *Conn) rcv() ([]byte, error) {
	c, err := client.DialTLS(usr.host+":"+strconv.FormatUint(usr.imapPort, 10), nil) // XXX: Not configuring TLS Config
	if err != nil {
		return nil, err
	}

	if err = c.Login(usr.uname, usr.password); err != nil {
		return nil, err
	}

	// XXX: Assumes inbox
	mbox, err := c.Select("INBOX", false)
	if err != nil {
		return nil, err
	}

	if mbox.Messages > usr.lastMessage {
		seqset := new(imap.SeqSet)
		seqset.AddRange(usr.lastMessage + 1, mbox.Messages)

		var section *imap.BodySectionName
		items := []imap.FetchItem{section.FetchItem()}

		messages := make(chan *imap.Message, 10)
		done := make(chan error, 1)
		go func() {
			done <- c.Fetch(seqset, items,  messages)
		}()

		var buf bytes.Buffer

		for recv := range messages {
			parsed := recv.GetBody(section)
			if parsed == nil {
				return nil, fmt.Errorf("Server didn't returned message body")
			}

			mr, err := mail.CreateReader(parsed)
			if err != nil {
				return nil, err
			}
			// See https://github.com/emersion/go-imap/wiki/Fetching-messages#fetching-the-whole-message-body
			for {
				p, err := mr.NextPart()
				if err == io.EOF {
					break
				} else if err != nil {
					return nil, err
				}

				switch p.Header.(type) {
				case *mail.InlineHeader:
					b, _ := ioutil.ReadAll(p.Body) // XXX: Should there be an err catch here?
					m, err := decrypt(b, []byte("raven_is_cool")) // NEXT: Change up password
					if err != nil {
						return nil, err
					}

					msg, err := em.decode(m)
					if err != nil {
						if err != ErrID {
							return nil, err
						}
						err = nil
					}
					buf.write(em.parse(msg))
				}
			}
		}

		if err := <-done; err != nil {
			return nil, err
		}
	}

	return buf.bytes(), nil
}

// ADDTEST
func (em *Conn) parse(msg frag) []byte {
	var buf bytes.Buffer
	if frag.index < em.rcvd {
		return nil
	}
	if frag.index == em.rcvd {
		buf.write(frag.content)
		if frag.last {
			em.closed = true
		}
		if len(em.frags) > 0 {
			nextFrag := em.frags[0]
			em.frags = em.frags[1:]
			next := em.parse(nextFrag)
			buf.write(next)
		}
	}
	if frag.index > em.rcvd {
		em.storeFrag(frag)
	}
	return buf.bytes()
	// TODO: If closed stop stuff
}

// ADDTEST
func (em *Conn) storeFrag(f frag) {
	for i, f_i := range em.frags {
		if f_i.index > f.index {
			em.frags = append(em.frags[:i], append([]frag{f},em.frags[i:]...)...)
			return
		}
	}
	append(em.frags, f)
}

// TODO: Some server listener
