package authenticators

import (
	"context"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type unauthorizedAuthenticator struct{}

func NewUnauthorizedAuthenticator() *unauthorizedAuthenticator {
	return &unauthorizedAuthenticator{}
}

func (a *unauthorizedAuthenticator) Authenticate(
	_ context.Context,
	_ handler.RequestContext,
	_ *heimdall.SubjectContext,
) error {
	return errorchain.NewWithMessage(heimdall.ErrAuthentication, "denied by authenticator")
}

func (a *unauthorizedAuthenticator) WithConfig(_ map[string]any) (handler.Authenticator, error) {
	// nothing can be reconfigured
	return a, nil
}
