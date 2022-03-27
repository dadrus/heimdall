package authenticators

import (
	"context"
	"encoding/json"

	"github.com/dadrus/heimdall/internal/errorsx"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/pipeline/interfaces"
)

type unauthorizedAuthenticator struct{}

func NewUnauthorizedAuthenticator() *unauthorizedAuthenticator {
	return &unauthorizedAuthenticator{}
}

func (a *unauthorizedAuthenticator) Authenticate(_ context.Context, _ interfaces.AuthDataSource, _ *heimdall.SubjectContext) error {
	return &errorsx.UnauthorizedError{Message: "denied by authenticator"}
}

func (a *unauthorizedAuthenticator) WithConfig(_ json.RawMessage) (pipeline.Authenticator, error) {
	// nothing can be reconfigured
	return a, nil
}
