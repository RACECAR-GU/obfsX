//
//	Golang implementation of Raven
//
//	Eliana Troper and Micah Sherr
//
// TODO: maybe take a look at https://github.com/emersion/go-pgpmail

package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/smtp"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "golang.org/x/crypto/ripemd160"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"github.com/emersion/go-message/mail"
	"github.com/google/uuid"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

// some protections
var check_mu sync.Mutex
var send_mu sync.Mutex
var sent_mu sync.Mutex
var imap_create_mu sync.Mutex
var smtp_create_mu sync.Mutex

type account struct {
	host     string
	smtpPort uint64
	imapPort uint64
	uname    string
	password string

	queue []*message

	slot_chan chan slot

	is_sent map[uuid.UUID]bool

	// a map, keyed by message UUID, of message groups. (a `msg_grp` is a slice
	// of fragments (chunks) belonging to a single message)
	re_grp map[uuid.UUID]*msg_grp

	// really bad to set this to true, will ignore TLS checks
	// (the default is that this is set to false)
	insecure_tls bool

	keyring raven_keyring

	imapClient *client.Client
	smtpClient *smtp.Client
}

func newAccount(host string, smtpPort uint64, imapPort uint64, uname string, password string, keyfile string) (*account, error) {
	res := &account{
		host:     host,
		smtpPort: smtpPort,
		imapPort: imapPort,
		uname:    uname,
		password: password,

		queue: make([]*message, 0),

		slot_chan: make(chan slot),

		is_sent: make(map[uuid.UUID]bool),

		re_grp: make(map[uuid.UUID]*msg_grp),

		insecure_tls: false,

		keyring: loadKeyRing(keyfile),
	}

	go SlotGenerator(res.slot_chan)
	return res, nil
}

func (usr *account) check_sent(id uuid.UUID, remove_if_sent bool) (bool, error) {
	sent, ok := usr.is_sent[id]
	if !ok {
		return false, fmt.Errorf("message not sent, or to be sent")
	}
	if sent && remove_if_sent {
		sent_mu.Lock()
		defer sent_mu.Unlock()
		delete(usr.is_sent, id)
	}
	return sent, nil
}

/**
 * this is essentially how you send a message -- you enqueue it
 */
func (usr *account) enqueue(rcvrs []string, b []byte) (id uuid.UUID, err error) {
	msg, err := newMessage(b)
	if err != nil {
		return uuid.Nil, err
	}
	msg.rcvrs = rcvrs
	usr.queue = append(usr.queue, msg)
	sent_mu.Lock()
	defer sent_mu.Unlock()
	usr.is_sent[msg.uuid] = false
	logDebug("enqueued message with UUID ", hex.EncodeToString(msg.uuid[:]), " and receivers={", rcvrs, "}")
	return msg.uuid, nil
}

func (usr *account) send() (err error) {
	send_mu.Lock()
	defer send_mu.Unlock()

	slot := <-usr.slot_chan
	//logDebug("time now is ", time.Now(), " and slot time is ", slot.time)
	if slot.time.Before(time.Now()) {
		if len(usr.queue) > 0 {
			err = usr.sendMsg(slot.size)
		} else {
			err = usr.sendDummy(slot.size)
		}
		if err != nil {
			return err
		}
		return nil
	}
	return nil
}

// kinda shocked that int max isn't build in somewhere
func min(x, y int) int {
	if x < y {
		return x
	} else {
		return y
	}
}

func (usr *account) sendDummy(size int) (err error) {
	rcvrs := []string{usr.uname} // we're just gonna send it to ourself
	chunk := make([]byte, size)  // NEXT: Get PGP overhead to reduce
	m, err := encrypt(chunk, "dummy", usr.keyring)
	if err != nil {
		return err
	}
	err = usr.sendMail(rcvrs, m)
	return err
}

