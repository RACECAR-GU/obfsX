package emily

import (
	"time"
	"bytes"

	"net/smtp"
)

type slot struct {
	time    time.Time
	size    int
	rcvr_ct int // MICAH: not sure what this is.  doesn't appear to be used anywhere
}

func (em *Conn) load_slots(to_load int) {
	// TODO
}

func (em *Conn) send(b []byte, offset int, s slot) (int, error) {
	to_send, send_content_len, err := em.encode(b, offset, s)
	if err != nil {
		return 0, err
	}

	m, err := encrypt(to_send, []byte("raven_is_cool")) // NEXT: Change up password
	if err != nil {
		return err
	}

	err := em.ail(m)
	if err != nil {
		return 0, err
	}
	em.sent += 1

	return send_content_len, nil
}
// send helpers
func (em *Conn) encode(b []byte, offset int, s slot) ([]byte, int, error) {
	buf := new(bytes.Buffer)

	max_content_len = s.size - 16 - 4 - 4 - 1
	last := false
	content_len = max_content_len
	if len(b) - offset <= max_content_len {
		last := true
		content_len = len(b[offset:])
	}
	// stream id			// 16 bytes
	err := binary.Write(buf, binary.LittleEndian, em.uuid)
	if err != nil {
		return nil, 0, err
	}
	// Add message number		// 4 bytes
	err := binary.Write(buf, binary.LittleEndian, em.sent)
	if err != nil {
		return nil, 0, err
	}
	// Add control byte		// 1 byte
	var ctrl uint8
	if last {
		ctrl += 1
	}
	err := binary.Write(buf, binary.LittleEndian, ctrl)
	if err != nil {
		return nil, 0, err
	}
	// Add length and content	// 4 bytes + ?
	err := binary.Write(buf, binary.LittleEndian, content_len)
	if err != nil {
		return nil, 0, err
	}
	err := buf.Write(b[offset:offset+content_len])
	if err != nil {
		return nil, 0, err
	}
	// Padding
	if content_len != max_content_len {
		err := buf.Write(make([]byte, max_content_len - content_len))
		if err != nil {
			return nil, 0, err
		}
	}
	return buf.bytes(), content_len, nil
}

/**
 * grabs messages off the queue and sends them
 */
func (usr *account) sendMsg(size int) (err error) {
	logDebug("sendMsg: queue has ", len(usr.queue), " messages")
	msg := usr.queue[0]
	logDebug("sendMsg: grabbing message off queue and prepping for send: ", msg, "; slot size is ", size)
	if len(msg.rcvrs) < 1 || len(msg.rcvrs[0]) < 1 {
		logWarning("sendMsg: no receivers or empty ('') receiver specified, so marking message as being sent")
		// TODO: shouldn't the next line be within a Lock() Unlock() stanza?
		usr.queue = usr.queue[1:] // dequeue (i.e., mark message as sent!)
		sent_mu.Lock()
		defer sent_mu.Unlock()
		usr.is_sent[msg.uuid] = true
		return nil
	}
	chunk, pld_size, err := msg.makeChunk(size) // NEXT: Get PGP overhead to reduce
	if err != nil {
		logWarning("makeChunk returned an error: ", err)
		// TODO: shouldn't the next line be within a Lock() Unlock() stanza?
		usr.queue = usr.queue[1:] // XXX: This ain't the best, should catch this before enqueueing
		return err
	}
	m, err := encrypt(chunk, msg.rcvrs[0], usr.keyring)
	if err != nil {
		return err
	}
	err = usr.sendMail(msg.rcvrs, m)
	if err != nil {
		logError("sendMail returned an error: ", err)
		return err
	} else {
		log.Println("sent email")
	}
	if pld_size >= 0 { // If we didn't send the remainder of the message
		msg.msg = msg.msg[pld_size:]
		msg.sent_frags += 1
	} else {
		logDebug("completed sending message with UUID ", hex.EncodeToString(msg.uuid[:]))
		usr.queue = usr.queue[1:] // dequeue (i.e., mark message as sent!)
		sent_mu.Lock()
		defer sent_mu.Unlock()
		usr.is_sent[msg.uuid] = true
	}
	return nil
}

/*
	actually use SMTP to send amessage

	`pld` is the actual message to send
*/
func (em *Conn) ail(rcvrs []string, pld []byte) error {
	var err error

	smtp_create_mu.Lock()
	if usr.smtpClient == nil {
		auth := smtp.PlainAuth("", usr.uname, usr.password, usr.host)
		servername := usr.host + ":" + strconv.FormatUint(usr.smtpPort, 10)

		tlsconfig := &tls.Config{
			InsecureSkipVerify: usr.insecure_tls, // DANGER!
			ServerName:         usr.host,
		}
		usr.smtpClient, err = smtp.Dial(servername)
		if err != nil {
			logError("cannot connect (smtp.Dial failed connecting to ", servername, "): ", err)
			smtp_create_mu.Unlock()
			return err
		}
		if err = usr.smtpClient.Hello(usr.host); err != nil {
			logError(err)
			smtp_create_mu.Unlock()
			return err
		}
		if err = usr.smtpClient.StartTLS(tlsconfig); err != nil {
			logError(err)
			smtp_create_mu.Unlock()
			return err
		}
		if err = usr.smtpClient.Auth(auth); err != nil {
			logError(err)
			smtp_create_mu.Unlock()
			return err
		}
	} else {
		// TODO: send a RST
	}
	smtp_create_mu.Unlock()

	// send a message
	receivers_as_string := strings.Join(rcvrs, ",")
	header := []byte("To: " + receivers_as_string + "\r\n" +
		"From: " + usr.uname + "\r\n" +
		"Subject: Totally legit message\r\n" +
		"\r\n")

	if err = usr.smtpClient.Mail(usr.uname); err != nil {
		logError(err)
		return err
	}
	for _, receiver := range rcvrs {
		if err = usr.smtpClient.Rcpt(receiver); err != nil {
			logError(err)
			return err
		}
	}
	// Data
	w, err := usr.smtpClient.Data()
	if err != nil {
		logError(err)
		return err
	}
	if _, err = w.Write([]byte(header)); err != nil {
		logError(err)
		return err
	}
	if _, err = w.Write(pld); err != nil {
		logError(err)
		return err
	}
	w.Close()

	/*
		// let's go ahead and keep the connection alive.
		if err = client.Quit(); err != nil {
			logError(err)
			return err
		}
	*/
	return nil
}
