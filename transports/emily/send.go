package emily

import (
	"time"
	"bytes"
	
	"net/smtp"
)

type slot struct {
	time		time.Time
	size		uint32
}

func (em *Conn) load_slots(to_load int) {
	// TODO
}

func (em *Conn) send(b []byte, offset int, s slot) (int, error) {
	to_send, send_content_len, err := em.encode(b, offset, s)
	if err != nil {
		return 0, err
	}
	
	m, err := encrypt(to_send, []byte("raven_is_cool")) // TODO: Write encrypt // NEXT: Change up password
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
func (em *Conn) ail(m []byte) error {
	auth := smtp.PlainAuth("", em.uname, em.password, em.host)
		// Note that this fails w/o TLS.
	return smtp.SendMail(em.host+":"+strconv.FormatUint(em.smtpPort, 10), auth, em.uname, em.rcvrs, pld)
}
