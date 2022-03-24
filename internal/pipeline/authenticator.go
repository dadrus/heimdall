package pipeline

import (
	"context"

	"github.com/dadrus/heimdall/internal/heimdall"
)

type Authenticator interface {
	Authenticate(context.Context, AuthDataSource, *heimdall.SubjectContext) error
}
