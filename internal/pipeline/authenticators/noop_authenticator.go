package authenticators

import (
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerAuthenticatorTypeFactory(
		func(typ config.PipelineObjectType, conf map[string]any) (bool, Authenticator, error) {
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

func (a *noopAuthenticator) WithConfig(_ map[string]any) (Authenticator, error) {
	// nothing can be reconfigured
	return a, nil
}
