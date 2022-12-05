package authenticators

import (
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerAuthenticatorTypeFactory(
		func(id string, typ string, conf map[string]any) (bool, Authenticator, error) {
			if typ != AuthenticatorUnauthorized {
				return false, nil, nil
			}

			return true, newUnauthorizedAuthenticator(id), nil
		})
}

type unauthorizedAuthenticator struct {
	id string
}

func newUnauthorizedAuthenticator(id string) *unauthorizedAuthenticator {
	return &unauthorizedAuthenticator{id: id}
}

func (a *unauthorizedAuthenticator) Execute(ctx heimdall.Context) (*subject.Subject, error) {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Authenticating using unauthorized authenticator")

	return nil, errorchain.
		NewWithMessage(heimdall.ErrAuthentication, "denied by authenticator").
		WithErrorContext(a)
}

func (a *unauthorizedAuthenticator) WithConfig(_ map[string]any) (Authenticator, error) {
	// nothing can be reconfigured
	return a, nil
}

func (a *unauthorizedAuthenticator) IsFallbackOnErrorAllowed() bool {
	// not allowed, as this authenticator fails always
	return false
}

func (a *unauthorizedAuthenticator) HandlerID() string {
	return a.id
}
