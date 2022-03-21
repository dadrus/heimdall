package authenticators

var _ Authenticator = new(unauthorizedAuthenticator)

func newUnauthorizedAuthenticator(id string) (*unauthorizedAuthenticator, error) {
	return &unauthorizedAuthenticator{
		id: id,
	}, nil
}

type unauthorizedAuthenticator struct {
	id string
}

func (a *unauthorizedAuthenticator) Id() string {
	return a.id
}

func (a *unauthorizedAuthenticator) Authenticate() error {
	return nil
}
