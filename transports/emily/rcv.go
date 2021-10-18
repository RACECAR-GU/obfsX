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

func (usr *account) rcv() ([][]byte, error) {

	var err error

	imap_create_mu.Lock() // only allow one creation of an imap instance
	if usr.imapClient == nil {
		logDebug("creating new imap instance")
		if usr.insecure_tls {
			logWarning("using insecure TLS connection")
			tlsconfig := &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         usr.host,
			}
			usr.imapClient, err = client.DialTLS(usr.host+":"+strconv.FormatUint(usr.imapPort, 10), tlsconfig)
		} else {
			usr.imapClient, err = client.DialTLS(usr.host+":"+strconv.FormatUint(usr.imapPort, 10), nil)
		}
		if err != nil {
			logError("imap.DialTLS error:", err)
			imap_create_mu.Unlock()
			return nil, err
		}
		if err = usr.imapClient.Login(usr.uname, usr.password); err != nil {
			logError("cannot log in to IMAP server: using username ", usr.uname)
			imap_create_mu.Unlock()
			return nil, err
		}
	} else {
		logDebug("using existing imap instance")
	}
	imap_create_mu.Unlock()

	// only one check at a time
	check_mu.Lock()
	defer check_mu.Unlock()

	mbox, err := usr.imapClient.Select("INBOX", false)
	if err != nil {
		return nil, err
	}
	logDebug("mailbox contains ", mbox.Messages, " messages")

	res := make([][]byte, 0) // hold the results

	// fetch only the unread emails
	criteria := imap.NewSearchCriteria()
	criteria.WithoutFlags = []string{"\\Seen"}
	uids, err := usr.imapClient.Search(criteria)
	if err != nil {
		logError(err)
	}
	if len(uids) > 0 {
		//uids = uids[0:1]
		logDebug("grabbing new email with UID=", uids)
		seqset := new(imap.SeqSet)
		seqset.AddNum(uids...)

		var section imap.BodySectionName
		items := []imap.FetchItem{section.FetchItem()}

		messages := make(chan *imap.Message, 1)
		done := make(chan error, 1)
		go func() {
			done <- usr.imapClient.Fetch(seqset, items, messages)
		}()

		var parsed imap.Literal
		for recv := range messages {
			for attempts := 0; attempts < 3; attempts++ {
				parsed = recv.GetBody(&section)
				if parsed == nil {
					logWarning("IMAP server didn't return message body for msg with uid ", uids, ". Waiting a few ms and will try again.")
					time.Sleep(time.Millisecond * 100)
				} else {
					break
				}
			}
			if parsed == nil {
				logDebug("IMAP server failed to get body for message:\n", recv)
				return nil, fmt.Errorf("IMAP server didn't return message body")
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
					b, _ := ioutil.ReadAll(p.Body)
					d, err := decrypt(b, usr.keyring, usr.uname)
					if d != nil {
						r, err := usr.deChunk(d)
						if err != nil {
							return nil, err
						}
						if r != nil {
							res = append(res, r)
						}
					} else if err != nil {
						if err == io.EOF {
							continue
						} else {
							return nil, err
						}
					}
				}
			}
		}

		if err := <-done; err != nil {
			return nil, err
		}
	}
	logDebug("rcv() returning with a decrypted message")
	return res, nil
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
