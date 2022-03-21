package authenticators

var _ Authenticator = new(noopAuthenticator)

func newNoopAuthenticator(id string) (*noopAuthenticator, error) {
	return &noopAuthenticator{
		id: id,
	}, nil
}

type noopAuthenticator struct {
	id string
}

func (a *noopAuthenticator) Id() string {
	return a.id
}

func (*noopAuthenticator) Authenticate() error {
	return nil
}
