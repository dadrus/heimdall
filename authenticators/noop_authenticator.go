package authenticators

import (
	"context"

	"github.com/dadrus/heimdall/pipeline"
)

var _ Authenticator = new(noopAuthenticator)

func newNoopAuthenticator() (*noopAuthenticator, error) {
	return &noopAuthenticator{}, nil
}

type noopAuthenticator struct{}

func (*noopAuthenticator) Authenticate(ctx context.Context, as pipeline.AuthDataSource, sc *pipeline.SubjectContext) error {
	return nil
}
