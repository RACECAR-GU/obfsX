package emily

import (
	"bytes"
	"errors"
)

var ErrID = errors.New("rcv: Wrong conn id")

func (em *Conn) rcv(b []byte, offset int, s slot) (int, error) {
	
}
// send helpers
func (em *Conn) decode(b []byte) ([]byte, uint32, bool, error) {
	buf := bytes.NewReader(b)
	
	// stream id
	var uuid [16]byte
	err := binary.read(buf, binary.LittleEndian, &uuid)
	if err != nil {
		return nil, 0, false, err
	}
	if uuid != em.uuid {
		return nil, 0, false, ErrID // TODO: Catch this and continue
	}
	
	// message number
	var rcv_i uint32
	err := binary.read(buf, binary.LittleEndian, &rcv_i)
	if err != nil {
		return nil, 0, false, err
	}
	
	// controls
	var ctrl uint8
	err := binary.read(buf, binary.LittleEndian, &ctrl)
	if err != nil {
		return nil, 0, false, err
	}
	last := false
	if ctrl % 2 == 1 {
		last = true
	}
	
	// content length
	var size uint32
	err := binary.read(buf, binary.LittleEndian, &size)
	if err != nil {
		return nil, 0, false, err
	}
	
	content := make([]byte, size)
	_, err := buf.read(content)
	if err != nil {
		return nil, 0, false, err
	}
	
	return content, rcv_i, last, nil
	
}
// TODO: Read from inbox

func (em *Conn) ([]byte, error) {
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
					m, err := encrypt(b, []byte("raven_is_cool")) // NEXT: Change up password// TODO: Decrypt
					if err != nil {
						return nil, err
					}
					
					content, rcv_i, last, err := em.decode(m)
					if err != nil {
						if err != ErrID {
							return nil, err
						}
						err = nil
					}
					
					// TODO: Combine these messages
				}
			}
		}

		if err := <-done; err != nil {
			return nil, err
		}
	}

	return res, nil
}
