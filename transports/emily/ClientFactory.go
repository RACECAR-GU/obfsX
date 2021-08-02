
package emily

// returns a new ClientFactory instance.
func (t *Transport) ClientFactory(stateDir string) (base.ClientFactory, error) {
	cf := new(ClientFactory)
	return cf, nil
}

type ClientFactory struct {
	transport base.Transport
}

func (cf *ClientFactory) Transport() base.Transport {
	return cf.transport
}

func (cf *ClientFactory) ParseArgs(args *pt.Args) (interface{}, error) {
	// NEXT
}

func (cf *ClientFactory) Dial(network, addr string, dialer net.Dialer, args interface{}) (net.Conn, error) {
	// NEXT
	return conn, nil
}
