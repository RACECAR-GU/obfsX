package emily

type message struct {
	rcvrs      []string
	msg        []byte
	uuid       [16]byte
	sent_frags uint64
}
// a string formatter for messages, to make it pretty
func (m message) String() (res string) {
	hash := sha256.Sum256(m.msg)
	if len(m.msg) < 64 {
		res = fmt.Sprintf("{uuid=%v;recvrs=%v;sent_frags=%v,len=%d,msg_hash=%v,msg=\"%v\"}",
			hex.EncodeToString(m.uuid[:]), m.rcvrs, m.sent_frags, len(m.msg),
			hex.EncodeToString(hash[:]),
			string(m.msg))
	} else {
		// message is fairly big, so just return its hash value
		res = fmt.Sprintf("{uuid=%v;recvrs=%v;sent_frags=%v,len=%d,msg_hash=%v}",
			hex.EncodeToString(m.uuid[:]), m.rcvrs, m.sent_frags, len(m.msg),
			hex.EncodeToString(hash[:]))
	}
	return // returns res
}

func newMessage(b []byte) (msg *message, err error) {
	// Test X
	msg = new(message)
	msg.uuid, err = uuid.NewRandom()
	if err != nil {
		return nil, err
	}
	msg.msg = b
	msg.sent_frags = 0

	return msg, nil
}

/**
Generates a chunk (fragment) to send.  `size` is the max size of the chunk to
send.

Returns the bytes to send including the chunk header and payload (i.e,. the
chunk), the size of that chunk, and (hopefully not) an error.
*/
func (msg *message) makeChunk(chunk_size int) ([]byte, int, error) {
	// Test X

	// A chunk is
	//	uuid (16 bytes)
	//	frag info (1 byte: 1 bit is_last, 7 bit int)
	//	if is_last:
	//		length (4 bytes)
	//		payload (remaining payload bytes)
	//		padding (size - 16 - 1 - 4 - len(payload))
	//	else:
	//		payload (size - 16 - 1 bytes)

	buf := new(bytes.Buffer)
	if n, _ := buf.Write(msg.uuid[:]); n != 16 {
		return nil, -1, fmt.Errorf("makeChunk: err copying uuid")
	}

	if msg.sent_frags > 127 {
		return nil, -1, fmt.Errorf("makeChunk: index out of range")
	}
	if len(msg.msg) <= chunk_size-16-1-4 {
		// Pack all
		frag_info := uint8((1 << 7) + msg.sent_frags)
		buf.WriteByte(frag_info)
		length := uint32(len(msg.msg))
		binary.Write(buf, binary.LittleEndian, length)
		buf.Write(msg.msg)
		return buf.Bytes()[:], -1, nil
	} else {
		// Pack some
		length := len(msg.msg)
		pld_size := min(length, chunk_size)
		frag_info := uint8(msg.sent_frags)
		buf.WriteByte(frag_info)
		buf.Write(msg.msg[:pld_size])
		return buf.Bytes()[:], pld_size, nil
	}
}

// message fragment
type msg_frg struct {
	frag_num uint // probably should be a uint8
	pld      []byte
}

/*
This function does quite a bit.

it takes a chunk (i.e., the contents of an email), and produces a message
fragment (msg_frg).  It then checks whether that message belongs to an existing
message group (msg_grp).  If it doesn't, it creates one.  Otherwise, it appends
it to that group.

Finally, if all message fragments have arrived, it calls reconstruct() to
reconstruct the final message.
*/
func (usr *account) deChunk(raw []byte) ([]byte, error) {

	this_fragment := new(msg_frg)

	reader := bytes.NewBuffer(raw)
	id, err := uuid.FromBytes(reader.Next(16)[:])
	if err != nil {
		return nil, err
	}
	// A chunk is
	//	uuid (16 bytes)
	//	frag info (1 byte: 1 bit is_last, 7 bit int)
	//	if is_last:
	//		length (4 bytes)
	//		payload (remaining payload bytes)
	//		padding (size - 16 - 1 - 4 - len(payload))
	//	else:
	//		payload (size - 16 - 1 bytes)

	frag_info, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	is_last := false
	if frag_info >= (1 << 7) {
		is_last = true
		this_fragment.frag_num = uint(frag_info) - (1 << 7)
	} else {
		this_fragment.frag_num = uint(frag_info)
	}
	if !is_last {
		this_fragment.pld = reader.Bytes()[:]
	} else {
		length_packed := reader.Next(4)[:]
		var length uint32
		len_reader := bytes.NewReader(length_packed)
		binary.Read(len_reader, binary.LittleEndian, &length)
		this_fragment.pld = reader.Next(int(length))[:]
	}
	grp, ok := usr.re_grp[id]
	if !ok {
		grp = new(msg_grp)
		grp.last = -1
		usr.re_grp[id] = grp
	}
	grp.frgs = append(grp.frgs, this_fragment)
	if is_last {
		grp.last = int(this_fragment.frag_num)
	}

	// This logic requires some explanation...
	// If (1) we received the last fragment (i.e., grp.last != -1) and (2) the
	// number of fragments we received (len(grp.frgs) equals the last fragment
	// number (minus 1, since we start counting at 0), then we have everything
	// and thus it's safe to reconstruct
	if (grp.last > -1) && (grp.last == (len(grp.frgs) - 1)) {
		logDebug("received all chunks for msg uid ", hex.EncodeToString(id[:]))
		b, err := grp.reconstruct()
		if err != nil {
			return nil, err
		}
		if b != nil {
			delete(usr.re_grp, id) // XXX: If some dupes arrive later...
		}
		return b, nil
	}
	// if it's not the last fragment, return nil
	logDebug("received a chunk for msg uid ",
		hex.EncodeToString(id[:]),
		", but haven't received all chunks; current frag group is ",
		grp)
	return nil, nil
}
