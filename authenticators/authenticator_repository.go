package authenticators

import (
	"errors"

	"github.com/dadrus/heimdall/config"
)

type AuthenticatorRepository interface {
	FindById(id string) (Authenticator, error)
}

func NewAuthenticatorRepository(conf config.Configuration) (AuthenticatorRepository, error) {
	var authenticators map[string]Authenticator
	for _, auth := range conf.Authenticators {
		if a, err := createAuthenticator(auth); err != nil {
			authenticators[auth.Id] = a
		} else {
			return nil, err
		}
	}
	return &authenticatorRepository{r: authenticators}, nil
}

func createAuthenticator(auth config.PipelineObject) (Authenticator, error) {
	switch auth.Type {
	case config.Noop:
		return newNoopAuthenticator(auth.Id)
	case config.Anonymous:
		return newAnonymousAuthenticator(auth.Id, auth.Config)
	case config.Unauthorized:
		return newUnauthorizedAuthenticator(auth.Id)
	case config.AuthenticationData:
		return newAuthenticationDataAuthenticator(auth.Id, auth.Config)
	case config.OAuth2Introspection:
		return nil, nil
	case config.Jwt:
		return nil, nil
	default:
		return nil, errors.New("unknown authenticator type")
	}
}

type authenticatorRepository struct {
	r map[string]Authenticator
}

func (r *authenticatorRepository) FindById(id string) (Authenticator, error) {
	if a, ok := r.r[id]; !ok {
		return nil, errors.New("no such authenticator")
	} else {
		return a, nil
	}
}
