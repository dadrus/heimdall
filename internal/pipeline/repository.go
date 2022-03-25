package pipeline

import (
	"errors"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/pipeline/authenticators"
	"github.com/dadrus/heimdall/internal/pipeline/authorizers"
	"github.com/dadrus/heimdall/internal/pipeline/error_handlers"
	"github.com/dadrus/heimdall/internal/pipeline/hydrators"
	"github.com/dadrus/heimdall/internal/pipeline/mutators"
)

type Repository interface {
	Authenticator(id string) (Authenticator, error)
	Authorizer(id string) (Authorizer, error)
	Hydrator(id string) (Hydrator, error)
	Mutator(id string) (Mutator, error)
	ErrorHandler(id string) (ErrorHandler, error)
}

func NewRepository(conf config.Configuration) (Repository, error) {
	var ans map[string]Authenticator
	for _, pe := range conf.Pipeline.Authenticators {
		if r, err := newAuthenticator(pe); err != nil {
			ans[pe.Id] = r
		} else {
			return nil, err
		}
	}

	var azs map[string]Authorizer
	for _, pe := range conf.Pipeline.Authorizers {
		if r, err := newAuthorizer(pe); err != nil {
			azs[pe.Id] = r
		} else {
			return nil, err
		}
	}

	var hs map[string]Hydrator
	for _, pe := range conf.Pipeline.Hydrators {
		if r, err := newHydrator(pe); err != nil {
			hs[pe.Id] = r
		} else {
			return nil, err
		}
	}

	var ms map[string]Mutator
	for _, pe := range conf.Pipeline.Mutators {
		if r, err := newMutator(pe); err != nil {
			ms[pe.Id] = r
		} else {
			return nil, err
		}
	}

	var ehs map[string]ErrorHandler
	for _, pe := range conf.Pipeline.ErrorHandlers {
		if r, err := newErrorHandler(pe); err != nil {
			ehs[pe.Id] = r
		} else {
			return nil, err
		}
	}

	return &authenticatorRepository{
		authenticators: ans,
		authorizers:    azs,
		hydrators:      hs,
		mutators:       ms,
		errorHandlers:  ehs,
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
	switch c.Type {
	case config.Allow:
		return authorizers.NewAllowAuthorizer(), nil
	case config.Deny:
		return authorizers.NewDenyAuthorizer(), nil
	case config.Remote:
		return authorizers.NewRemoteAuthorizerFromJSON(c.Config)
	default:
		return nil, errors.New("unknown authorizer type")
	}
}

func newHydrator(c config.PipelineObject) (Hydrator, error) {
	switch c.Type {
	case config.Default:
		return hydrators.NewDefaultHydratorFromJSON(c.Config)
	default:
		return nil, errors.New("unknown hydrator type")
	}
}

func newMutator(c config.PipelineObject) (Mutator, error) {
	switch c.Type {
	case config.Jwt:
		return mutators.NewJWTMutatorFromJSON(c.Config)
	case config.Header:
		return mutators.NewHeaderMutatorFromJSON(c.Config)
	case config.Cookie:
		return mutators.NewCookieMutatorFromJSON(c.Config)
	default:
		return nil, errors.New("unknown hydrator type")
	}
}

func newErrorHandler(c config.PipelineObject) (ErrorHandler, error) {
	switch c.Type {
	case config.Json:
		return error_handlers.NewJsonErrorHandlerFromJSON(c.Config)
	case config.Redirect:
		return error_handlers.NewRedirectErrorHandlerFromJSON(c.Config)
	default:
		return nil, errors.New("unknown error handler type")
	}
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
