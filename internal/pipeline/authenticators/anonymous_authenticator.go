package authenticators

import (
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerAuthenticatorTypeFactory(
		func(id string, typ config.PipelineHandlerType, conf map[string]any) (bool, Authenticator, error) {
			if typ != config.POTAnonymous {
				return false, nil, nil
			}

			auth, err := newAnonymousAuthenticator(id, conf)

			return true, auth, err
		})
}

func newAnonymousAuthenticator(id string, rawConfig map[string]any) (*anonymousAuthenticator, error) {
	var auth anonymousAuthenticator

	if err := decodeConfig(rawConfig, &auth); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to decode anonymous authenticator config").
			CausedBy(err)
	}

	if len(auth.Subject) == 0 {
		auth.Subject = "anonymous"
	}

	auth.id = id

	return &auth, nil
}

type anonymousAuthenticator struct {
	id      string
	Subject string `mapstructure:"subject"`
}

func (a *anonymousAuthenticator) Execute(ctx heimdall.Context) (*subject.Subject, error) {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Authenticating using anonymous authenticator")

	return &subject.Subject{ID: a.Subject}, nil
}

func (a *anonymousAuthenticator) WithConfig(config map[string]any) (Authenticator, error) {
	// this authenticator allows subject to be redefined on the rule level
	if len(config) == 0 {
		return a, nil
	}

	return newAnonymousAuthenticator(a.id, config)
}

func (a *anonymousAuthenticator) IsFallbackOnErrorAllowed() bool {
	// not allowed, as no error can happen when this authenticator is executed
	return false
}

func (a *anonymousAuthenticator) HandlerID() string {
	return a.id
}
