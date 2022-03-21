package authenticators

import "context"

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

func (*noopAuthenticator) Authenticate(ctx context.Context, as AuthDataSource, sc *SubjectContext) error {
	return nil
}
