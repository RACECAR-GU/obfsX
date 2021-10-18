package emily

// A msg_grp is a slice of fragments (chunks) belonging to a single message.
// `last` is -1 when the last frag_num isn't known, or otherwise the last
// frag_num.
type msg_grp struct {
	frgs []*msg_frg
	last int
}

func (grp *msg_grp) String() string {
	frag_num_list := make([]uint, 0)
	for _, frg := range grp.frgs {
		frag_num_list = append(frag_num_list, frg.frag_num)
	}

	return fmt.Sprintf("{msg_grp last=%v; num_frags_received=%d,frags=%v}",
		grp.last, len(grp.frgs), frag_num_list)
}

/**
attempts to construct a (high-level) message (i.e., what Alice wants
to send to Bob) based on a group of received messages (i.e., emails)
*/
func (grp *msg_grp) reconstruct() ([]byte, error) {
	// first step, reassemble fragments in order
	num_frags := len(grp.frgs)
	buf := make([][]byte, num_frags)
	for _, frg := range grp.frgs {
		if frg.frag_num >= uint(num_frags) {
			logWarning("last fragment arrived before others?")
			return nil, fmt.Errorf("last fragment arrived before others -- PROGRAMMING ERROR! :(")
		}
		buf[frg.frag_num] = frg.pld
	}
	// ok, now that we have it actually in order, let's just dump the results to
	// a super big buffer
	res := make([]byte, 0)
	for _, chk := range buf {
		res = append(res, chk...) // append chk slide to res
	}
	return res, nil
}
