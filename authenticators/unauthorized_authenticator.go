package authenticators

import (
	"context"

	"github.com/dadrus/heimdall/pipeline"
)

var _ Authenticator = new(unauthorizedAuthenticator)

func newUnauthorizedAuthenticator() (*unauthorizedAuthenticator, error) {
	return &unauthorizedAuthenticator{}, nil
}

type unauthorizedAuthenticator struct{}

func (a *unauthorizedAuthenticator) Authenticate(ctx context.Context, as pipeline.AuthDataSource, sc *pipeline.SubjectContext) error {
	return nil
}
