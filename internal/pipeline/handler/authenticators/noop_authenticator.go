package authenticators

import (
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
	"github.com/dadrus/heimdall/internal/pipeline/handler/subject"
)

type noopAuthenticator struct{}

func NewNoopAuthenticator() *noopAuthenticator {
	return &noopAuthenticator{}
}

func (*noopAuthenticator) Authenticate(ctx heimdall.Context) (*subject.Subject, error) {
	return &subject.Subject{}, nil
}

func (a *noopAuthenticator) WithConfig(_ map[string]any) (handler.Authenticator, error) {
	// nothing can be reconfigured
	return a, nil
}
