package authenticators

import (
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
	"github.com/dadrus/heimdall/internal/pipeline/handler/subject"
)

func init() {
	handler.RegisterAuthenticatorTypeFactory(
		func(typ config.PipelineObjectType, conf map[string]any) (bool, handler.Authenticator, error) {
			if typ != config.POTNoop {
				return false, nil, nil
			}

			return true, newNoopAuthenticator(), nil
		})
}

type noopAuthenticator struct{}

func newNoopAuthenticator() *noopAuthenticator {
	return &noopAuthenticator{}
}

func (*noopAuthenticator) Authenticate(ctx heimdall.Context) (*subject.Subject, error) {
	return &subject.Subject{}, nil
}

func (a *noopAuthenticator) WithConfig(_ map[string]any) (handler.Authenticator, error) {
	// nothing can be reconfigured
	return a, nil
}
