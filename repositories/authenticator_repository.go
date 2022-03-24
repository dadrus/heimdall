package repositories

import (
	"errors"

	"github.com/dadrus/heimdall/authenticators"
	"github.com/dadrus/heimdall/config"
	"github.com/dadrus/heimdall/pipeline"
)

type AuthenticatorRepository interface {
	FindById(id string) (pipeline.Authenticator, error)
}

func NewAuthenticatorRepository(conf config.Configuration) (AuthenticatorRepository, error) {
	var authenticators map[string]pipeline.Authenticator
	for _, auth := range conf.Authenticators {
		if a, err := newAuthenticator(auth); err != nil {
			authenticators[auth.Id] = a
		} else {
			return nil, err
		}
	}
	return &authenticatorRepository{r: authenticators}, nil
}

func newAuthenticator(auth config.PipelineObject) (pipeline.Authenticator, error) {
	switch auth.Type {
	case config.Noop:
		return &authenticators.NoopAuthenticator{}, nil
	case config.Anonymous:
		return NewAnonymousAuthenticatorFromJSON(auth.Config)
	case config.Unauthorized:
		return &authenticators.UnauthorizedAuthenticator{}, nil
	case config.AuthenticationData:
		return NewAuthenticationDataAuthenticatorFromJSON(auth.Config)
	case config.OAuth2Introspection:
		return NewOAuth2IntrospectionAuthenticatorFromJSON(auth.Config)
	case config.Jwt:
		return NewJwtAuthenticatorFromJSON(auth.Config)
	default:
		return nil, errors.New("unknown authenticator type")
	}
}

type authenticatorRepository struct {
	r map[string]pipeline.Authenticator
}

func (r *authenticatorRepository) FindById(id string) (pipeline.Authenticator, error) {
	if a, ok := r.r[id]; !ok {
		return nil, errors.New("no such authenticator")
	} else {
		return a, nil
	}
}
