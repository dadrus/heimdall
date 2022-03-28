package authenticators

import (
	"context"
	"encoding/json"

	"github.com/dadrus/heimdall/internal/errorsx"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
)

type unauthorizedAuthenticator struct{}

func NewUnauthorizedAuthenticator() *unauthorizedAuthenticator {
	return &unauthorizedAuthenticator{}
}

func (a *unauthorizedAuthenticator) Authenticate(_ context.Context, _ handler.RequestContext, _ *heimdall.SubjectContext) error {
	return &errorsx.UnauthorizedError{Message: "denied by authenticator"}
}

func (a *unauthorizedAuthenticator) WithConfig(_ json.RawMessage) (handler.Authenticator, error) {
	// nothing can be reconfigured
	return a, nil
}
