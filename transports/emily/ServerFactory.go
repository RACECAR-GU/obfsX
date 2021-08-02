
package emily

// ServerFactory returns a new ServerFactory instance.
func (t *Transport) ServerFactory(stateDir string, args *pt.Args) (s base.ServerFactory, err error) {
	sf := new(ServerFactory)
	return sf, nil
}

type ServerFactory struct {
	transport base.Transport
	args *pt.Args
}

func (sf *ServerFactory) Transport() base.Transport {
	return sf.transport
}

func (sf *ServerFactory) Args() *pt.Args {
	return sf.args
}

func (sf *ServerFactory) WrapConn(conn net.Conn) (net.Conn, error) {
	// NEXT
}
