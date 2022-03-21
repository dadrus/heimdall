package authenticators

type Authenticator interface {
	Id() string
	Authenticate() error
}
