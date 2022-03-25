package authenticators

import (
	"context"

	"github.com/dadrus/heimdall/internal/errorsx"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/interfaces"
)

type unauthorizedAuthenticator struct{}

func NewUnauthorizedAuthenticator() *unauthorizedAuthenticator {
	return &unauthorizedAuthenticator{}
}

func (a *unauthorizedAuthenticator) Authenticate(_ context.Context, _ interfaces.AuthDataSource, _ *heimdall.SubjectContext) error {
	return &errorsx.UnauthorizedError{Message: "denied by authenticator"}
}
