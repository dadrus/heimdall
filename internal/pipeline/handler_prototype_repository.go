package pipeline

import (
	"errors"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
	authenticators2 "github.com/dadrus/heimdall/internal/pipeline/handler/authenticators"
	authorizers2 "github.com/dadrus/heimdall/internal/pipeline/handler/authorizers"
	error_handlers2 "github.com/dadrus/heimdall/internal/pipeline/handler/error_handlers"
	"github.com/dadrus/heimdall/internal/pipeline/handler/hydrators"
	mutators2 "github.com/dadrus/heimdall/internal/pipeline/handler/mutators"
)

func newHandlerPrototypeRepository(conf config.Configuration) (*handlerPrototypeRepository, error) {
	var ans map[string]handler.Authenticator
	for _, pe := range conf.Pipeline.Authenticators {
		if r, err := newAuthenticator(pe); err != nil {
			ans[pe.Id] = r
		} else {
			return nil, err
		}
	}

	var azs map[string]handler.Authorizer
	for _, pe := range conf.Pipeline.Authorizers {
		if r, err := newAuthorizer(pe); err != nil {
			azs[pe.Id] = r
		} else {
			return nil, err
		}
	}

	var hs map[string]handler.Hydrator
	for _, pe := range conf.Pipeline.Hydrators {
		if r, err := newHydrator(pe); err != nil {
			hs[pe.Id] = r
		} else {
			return nil, err
		}
	}

	var ms map[string]handler.Mutator
	for _, pe := range conf.Pipeline.Mutators {
		if r, err := newMutator(pe); err != nil {
			ms[pe.Id] = r
		} else {
			return nil, err
		}
	}

	var ehs map[string]handler.ErrorHandler
	for _, pe := range conf.Pipeline.ErrorHandlers {
		if r, err := newErrorHandler(pe); err != nil {
			ehs[pe.Id] = r
		} else {
			return nil, err
		}
	}

	return &handlerPrototypeRepository{
		authenticators: ans,
		authorizers:    azs,
		hydrators:      hs,
		mutators:       ms,
		errorHandlers:  ehs,
	}, nil
}

func newAuthenticator(c config.PipelineObject) (handler.Authenticator, error) {
	switch c.Type {
	case config.Noop:
		return authenticators2.NewNoopAuthenticator(), nil
	case config.Anonymous:
		return authenticators2.NewAnonymousAuthenticatorFromYAML(c.Config)
	case config.Unauthorized:
		return authenticators2.NewUnauthorizedAuthenticator(), nil
	case config.AuthenticationData:
		return authenticators2.NewAuthenticationDataAuthenticatorFromYAML(c.Config)
	case config.OAuth2Introspection:
		return authenticators2.NewOAuth2IntrospectionAuthenticatorFromJSON(c.Config)
	case config.Jwt:
		return authenticators2.NewJwtAuthenticatorFromYAML(c.Config)
	default:
		return nil, errors.New("unknown authenticator type")
	}
}

func newAuthorizer(c config.PipelineObject) (handler.Authorizer, error) {
	switch c.Type {
	case config.Allow:
		return authorizers2.NewAllowAuthorizer(), nil
	case config.Deny:
		return authorizers2.NewDenyAuthorizer(), nil
	case config.Remote:
		return authorizers2.NewRemoteAuthorizerFromJSON(c.Config)
	default:
		return nil, errors.New("unknown authorizer type")
	}
}

func newHydrator(c config.PipelineObject) (handler.Hydrator, error) {
	switch c.Type {
	case config.Default:
		return hydrators.NewDefaultHydratorFromJSON(c.Config)
	default:
		return nil, errors.New("unknown hydrator type")
	}
}

func newMutator(c config.PipelineObject) (handler.Mutator, error) {
	switch c.Type {
	case config.Jwt:
		return mutators2.NewJWTMutatorFromJSON(c.Config)
	case config.Header:
		return mutators2.NewHeaderMutatorFromJSON(c.Config)
	case config.Cookie:
		return mutators2.NewCookieMutatorFromJSON(c.Config)
	default:
		return nil, errors.New("unknown hydrator type")
	}
}

func newErrorHandler(c config.PipelineObject) (handler.ErrorHandler, error) {
	switch c.Type {
	case config.Json:
		return error_handlers2.NewJsonErrorHandlerFromJSON(c.Config)
	case config.Redirect:
		return error_handlers2.NewRedirectErrorHandlerFromJSON(c.Config)
	default:
		return nil, errors.New("unknown error handler type")
	}
}

type handlerPrototypeRepository struct {
	authenticators map[string]handler.Authenticator
	authorizers    map[string]handler.Authorizer
	hydrators      map[string]handler.Hydrator
	mutators       map[string]handler.Mutator
	errorHandlers  map[string]handler.ErrorHandler
}

func (r *handlerPrototypeRepository) Authenticator(id string) (handler.Authenticator, error) {
	if a, ok := r.authenticators[id]; !ok {
		return nil, errors.New("no such authenticator")
	} else {
		return a, nil
	}
}
func (r *handlerPrototypeRepository) Authorizer(id string) (handler.Authorizer, error) {
	if a, ok := r.authorizers[id]; !ok {
		return nil, errors.New("no such authorizer")
	} else {
		return a, nil
	}
}
func (r *handlerPrototypeRepository) Hydrator(id string) (handler.Hydrator, error) {
	if a, ok := r.hydrators[id]; !ok {
		return nil, errors.New("no such hydrator")
	} else {
		return a, nil
	}
}
func (r *handlerPrototypeRepository) Mutator(id string) (handler.Mutator, error) {
	if a, ok := r.mutators[id]; !ok {
		return nil, errors.New("no such mutators")
	} else {
		return a, nil
	}
}
func (r *handlerPrototypeRepository) ErrorHandler(id string) (handler.ErrorHandler, error) {
	if a, ok := r.errorHandlers[id]; !ok {
		return nil, errors.New("no such error handler")
	} else {
		return a, nil
	}
}
