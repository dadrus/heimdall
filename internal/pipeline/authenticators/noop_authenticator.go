package authenticators

import (
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerAuthenticatorTypeFactory(
		func(_ string, typ string, conf map[string]any) (bool, Authenticator, error) {
			if typ != AuthenticatorNoop {
				return false, nil, nil
			}

			return true, newNoopAuthenticator(), nil
		})
}

type noopAuthenticator struct{}

func newNoopAuthenticator() *noopAuthenticator {
	return &noopAuthenticator{}
}

func (*noopAuthenticator) Execute(ctx heimdall.Context) (*subject.Subject, error) {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Authenticating using noop authenticator")

	return &subject.Subject{}, nil
}

func (a *noopAuthenticator) WithConfig(_ map[string]any) (Authenticator, error) {
	// nothing can be reconfigured
	return a, nil
}

func (a *noopAuthenticator) IsFallbackOnErrorAllowed() bool {
	// not allowed, as no error can happen when this authenticator is executed
	return false
}
