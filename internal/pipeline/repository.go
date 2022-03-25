package pipeline

import (
	"errors"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/pipeline/authenticators"
)

type Repository interface {
	Authenticator(id string) (Authenticator, error)
	Authorizer(id string) (Authorizer, error)
	Hydrator(id string) (Hydrator, error)
	Mutator(id string) (Mutator, error)
	ErrorHandler(id string) (ErrorHandler, error)
}

func NewRepository(conf config.Configuration) (Repository, error) {
	var authenticators map[string]Authenticator
	for _, authn := range conf.Pipeline.Authenticators {
		if r, err := newAuthenticator(authn); err != nil {
			authenticators[authn.Id] = r
		} else {
			return nil, err
		}
	}

	var authorizers map[string]Authorizer
	for _, authz := range conf.Pipeline.Authorizers {
		if r, err := newAuthorizer(authz); err != nil {
			authorizers[authz.Id] = r
		} else {
			return nil, err
		}
	}

	var hydrators map[string]Hydrator
	for _, h := range conf.Pipeline.Hydrators {
		if r, err := newHydrator(h); err != nil {
			hydrators[h.Id] = r
		} else {
			return nil, err
		}
	}

	var mutators map[string]Mutator
	for _, m := range conf.Pipeline.Mutators {
		if r, err := newMutator(m); err != nil {
			mutators[m.Id] = r
		} else {
			return nil, err
		}
	}

	var errorHandlers map[string]ErrorHandler
	for _, e := range conf.Pipeline.ErrorHandlers {
		if r, err := newErrorHandler(e); err != nil {
			errorHandlers[e.Id] = r
		} else {
			return nil, err
		}
	}

	return &authenticatorRepository{
		authenticators: authenticators,
		authorizers:    authorizers,
		hydrators:      hydrators,
		mutators:       mutators,
		errorHandlers:  errorHandlers,
	}, nil
}

func newAuthenticator(c config.PipelineObject) (Authenticator, error) {
	switch c.Type {
	case config.Noop:
		return authenticators.NewNoopAuthenticator(), nil
	case config.Anonymous:
		return authenticators.NewAnonymousAuthenticatorFromJSON(c.Config)
	case config.Unauthorized:
		return authenticators.NewUnauthorizedAuthenticator(), nil
	case config.AuthenticationData:
		return authenticators.NewAuthenticationDataAuthenticatorFromJSON(c.Config)
	case config.OAuth2Introspection:
		return authenticators.NewOAuth2IntrospectionAuthenticatorFromJSON(c.Config)
	case config.Jwt:
		return authenticators.NewJwtAuthenticatorFromJSON(c.Config)
	default:
		return nil, errors.New("unknown authenticator type")
	}
}

func newAuthorizer(c config.PipelineObject) (Authorizer, error) {
	return nil, nil
}

func newHydrator(c config.PipelineObject) (Hydrator, error) {
	return nil, nil
}

func newMutator(c config.PipelineObject) (Mutator, error) {
	return nil, nil
}

func newErrorHandler(c config.PipelineObject) (ErrorHandler, error) {
	return nil, nil
}

type authenticatorRepository struct {
	authenticators map[string]Authenticator
	authorizers    map[string]Authorizer
	hydrators      map[string]Hydrator
	mutators       map[string]Mutator
	errorHandlers  map[string]ErrorHandler
}

func (r *authenticatorRepository) Authenticator(id string) (Authenticator, error) {
	if a, ok := r.authenticators[id]; !ok {
		return nil, errors.New("no such authenticator")
	} else {
		return a, nil
	}
}

func (r *authenticatorRepository) Authorizer(id string) (Authorizer, error) {
	if a, ok := r.authorizers[id]; !ok {
		return nil, errors.New("no such authorizer")
	} else {
		return a, nil
	}
}
func (r *authenticatorRepository) Hydrator(id string) (Hydrator, error) {
	if a, ok := r.hydrators[id]; !ok {
		return nil, errors.New("no such hydrator")
	} else {
		return a, nil
	}
}
func (r *authenticatorRepository) Mutator(id string) (Mutator, error) {
	if a, ok := r.mutators[id]; !ok {
		return nil, errors.New("no such mutators")
	} else {
		return a, nil
	}
}
func (r *authenticatorRepository) ErrorHandler(id string) (ErrorHandler, error) {
	if a, ok := r.errorHandlers[id]; !ok {
		return nil, errors.New("no such error handler")
	} else {
		return a, nil
	}
}
