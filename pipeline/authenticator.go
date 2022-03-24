package pipeline

import (
	"context"
)

type Authenticator interface {
	Authenticate(context.Context, AuthDataSource, *SubjectContext) error
}
