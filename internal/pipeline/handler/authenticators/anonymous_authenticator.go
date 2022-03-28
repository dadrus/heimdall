package authenticators

import (
	"context"

	"gopkg.in/yaml.v2"

	"github.com/dadrus/heimdall/internal/errorsx"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
)

func NewAnonymousAuthenticatorFromYAML(rawConfig []byte) (*anonymousAuthenticator, error) {
	var a anonymousAuthenticator

	if err := yaml.Unmarshal(rawConfig, &a); err != nil {
		return nil, &errorsx.ArgumentError{
			Message: "failed to unmarshal config",
			Cause:   err,
		}
	}

	if len(a.Subject) == 0 {
		a.Subject = "anonymous"
	}

	return &a, nil
}

type anonymousAuthenticator struct {
	Subject string `yaml:"subject"`
}

func (a *anonymousAuthenticator) Authenticate(_ context.Context, _ handler.RequestContext, sc *heimdall.SubjectContext) error {
	sc.Subject = &heimdall.Subject{Id: a.Subject}
	return nil
}

func (a *anonymousAuthenticator) WithConfig(config []byte) (handler.Authenticator, error) {
	// this authenticator allows subject to be redefined on the rule level
	if len(config) == 0 {
		return a, nil
	}

	return NewAnonymousAuthenticatorFromYAML(config)
}
