package authenticators

import (
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
	"github.com/dadrus/heimdall/internal/pipeline/handler/subject"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func NewAnonymousAuthenticator(rawConfig map[string]any) (*anonymousAuthenticator, error) {
	var auth anonymousAuthenticator

	if err := decodeConfig(rawConfig, &auth); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to decode anonymous authenticator config").
			CausedBy(err)
	}

	if len(auth.Subject) == 0 {
		auth.Subject = "anonymous"
	}

	return &auth, nil
}

type anonymousAuthenticator struct {
	Subject string `mapstructure:"subject"`
}

func (a *anonymousAuthenticator) Authenticate(ctx heimdall.Context) (*subject.Subject, error) {
	return &subject.Subject{ID: a.Subject}, nil
}

func (a *anonymousAuthenticator) WithConfig(config map[string]any) (handler.Authenticator, error) {
	// this authenticator allows subject to be redefined on the rule level
	if len(config) == 0 {
		return a, nil
	}

	return NewAnonymousAuthenticator(config)
}
