package authenticators

import (
	"context"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
)

type noopAuthenticator struct{}

func NewNoopAuthenticator() *noopAuthenticator {
	return &noopAuthenticator{}
}

func (*noopAuthenticator) Authenticate(_ context.Context, _ handler.RequestContext, sc *heimdall.SubjectContext) error {
	sc.Subject = &heimdall.Subject{}
	return nil
}

func (a *noopAuthenticator) WithConfig(_ []byte) (handler.Authenticator, error) {
	// nothing can be reconfigured
	return a, nil
}
