package authenticators

import (
	"context"

	"gopkg.in/yaml.v2"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func NewAnonymousAuthenticatorFromYAML(rawConfig []byte) (*anonymousAuthenticator, error) {
	var auth anonymousAuthenticator

	if err := yaml.UnmarshalStrict(rawConfig, &auth); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to unmarshal anonymous authenticator config").
			CausedBy(err)
	}

	if len(auth.Subject) == 0 {
		auth.Subject = "anonymous"
	}

	return &auth, nil
}

type anonymousAuthenticator struct {
	Subject string `yaml:"subject"`
}

func (a *anonymousAuthenticator) Authenticate(
	_ context.Context,
	_ handler.RequestContext,
	sc *heimdall.SubjectContext,
) error {
	sc.Subject = &heimdall.Subject{ID: a.Subject}

	return nil
}

func (a *anonymousAuthenticator) WithConfig(config []byte) (handler.Authenticator, error) {
	// this authenticator allows subject to be redefined on the rule level
	if len(config) == 0 {
		return a, nil
	}

	return NewAnonymousAuthenticatorFromYAML(config)
}
