package authenticators

import "context"

type Authenticator interface {
	Id() string
	Authenticate(context.Context, AuthDataSource, *SubjectContext) error
}
