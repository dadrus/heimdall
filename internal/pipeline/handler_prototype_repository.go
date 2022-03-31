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

var (
	ErrUnknownAuthenticatorType = errors.New("unknown authenticator type")
	ErrUnknownAuthorizerType    = errors.New("unknown authorizer type")
	ErrUnknownHydratorType      = errors.New("unknown hydrator type")
	ErrUnknownMutatorType       = errors.New("unknown mutator type")
	ErrUnknownErrorHandlerType  = errors.New("unknown error handler type")

	ErrNoSuchAuthenticator = errors.New("no such authenticator")
	ErrNoSuchAuthorizer    = errors.New("no such authorizer")
	ErrNoSuchHydrator      = errors.New("no such hydrator")
	ErrNoSuchMutator       = errors.New("no such mutator")
	ErrNoSuchErrorHandler  = errors.New("no such error handler")
)

func newHandlerPrototypeRepository(conf config.Configuration) (*handlerPrototypeRepository, error) {
	authenticatorMap, err := createPipelineObjects(conf.Pipeline.Authenticators, newAuthenticator)
	if err != nil {
		return nil, err
	}

	authorizerMap, err := createPipelineObjects(conf.Pipeline.Authorizers, newAuthorizer)
	if err != nil {
		return nil, err
	}

	hydratorMap, err := createPipelineObjects(conf.Pipeline.Hydrators, newHydrator)
	if err != nil {
		return nil, err
	}

	mutatorMap, err := createPipelineObjects(conf.Pipeline.Mutators, newMutator)
	if err != nil {
		return nil, err
	}

	ehMap, err := createPipelineObjects(conf.Pipeline.ErrorHandlers, newErrorHandler)
	if err != nil {
		return nil, err
	}

	return &handlerPrototypeRepository{
		authenticators: authenticatorMap,
		authorizers:    authorizerMap,
		hydrators:      hydratorMap,
		mutators:       mutatorMap,
		errorHandlers:  ehMap,
	}, nil
}

func createPipelineObjects[T any](
	pObjects []config.PipelineObject,
	create func(obj config.PipelineObject) (T, error),
) (map[string]T, error) {
	var objects map[string]T

	for _, pe := range pObjects {
		if r, err := create(pe); err != nil {
			objects[pe.Id] = r
		} else {
			return nil, err
		}
	}

	return objects, nil
}

func newAuthenticator(obj config.PipelineObject) (handler.Authenticator, error) {
	switch obj.Type {
	case config.POTNoop:
		return authenticators2.NewNoopAuthenticator(), nil
	case config.POTAnonymous:
		return authenticators2.NewAnonymousAuthenticatorFromYAML(obj.Config)
	case config.POTUnauthorized:
		return authenticators2.NewUnauthorizedAuthenticator(), nil
	case config.POTAuthenticationData:
		return authenticators2.NewAuthenticationDataAuthenticatorFromYAML(obj.Config)
	case config.POTOAuth2Introspection:
		return authenticators2.NewOAuth2IntrospectionAuthenticatorFromJSON(obj.Config)
	case config.POTJwt:
		return authenticators2.NewJwtAuthenticatorFromYAML(obj.Config)
	default:
		return nil, ErrUnknownAuthenticatorType
	}
}

func newAuthorizer(obj config.PipelineObject) (handler.Authorizer, error) {
	switch obj.Type {
	case config.POTAllow:
		return authorizers2.NewAllowAuthorizer(), nil
	case config.POTDeny:
		return authorizers2.NewDenyAuthorizer(), nil
	case config.POTRemote:
		return authorizers2.NewRemoteAuthorizerFromJSON(obj.Config)
	default:
		return nil, ErrUnknownAuthorizerType
	}
}

func newHydrator(obj config.PipelineObject) (handler.Hydrator, error) {
	switch obj.Type {
	case config.POTDefault:
		return hydrators.NewDefaultHydratorFromJSON(obj.Config)
	default:
		return nil, ErrUnknownHydratorType
	}
}

func newMutator(obj config.PipelineObject) (handler.Mutator, error) {
	switch obj.Type {
	case config.POTJwt:
		return mutators2.NewJWTMutatorFromJSON(obj.Config)
	case config.POTHeader:
		return mutators2.NewHeaderMutatorFromJSON(obj.Config)
	case config.POTCookie:
		return mutators2.NewCookieMutatorFromJSON(obj.Config)
	default:
		return nil, ErrUnknownMutatorType
	}
}

func newErrorHandler(obj config.PipelineObject) (handler.ErrorHandler, error) {
	switch obj.Type {
	case config.POTJson:
		return error_handlers2.NewJsonErrorHandlerFromJSON(obj.Config)
	case config.POTRedirect:
		return error_handlers2.NewRedirectErrorHandlerFromJSON(obj.Config)
	default:
		return nil, ErrUnknownErrorHandlerType
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
	a, ok := r.authenticators[id]
	if !ok {
		return nil, ErrNoSuchAuthenticator
	}

	return a, nil
}

func (r *handlerPrototypeRepository) Authorizer(id string) (handler.Authorizer, error) {
	a, ok := r.authorizers[id]
	if !ok {
		return nil, ErrNoSuchAuthorizer
	}

	return a, nil
}

func (r *handlerPrototypeRepository) Hydrator(id string) (handler.Hydrator, error) {
	a, ok := r.hydrators[id]
	if !ok {
		return nil, ErrNoSuchHydrator
	}

	return a, nil
}

func (r *handlerPrototypeRepository) Mutator(id string) (handler.Mutator, error) {
	a, ok := r.mutators[id]
	if !ok {
		return nil, ErrNoSuchMutator
	}

	return a, nil
}

func (r *handlerPrototypeRepository) ErrorHandler(id string) (handler.ErrorHandler, error) {
	a, ok := r.errorHandlers[id]
	if !ok {
		return nil, ErrNoSuchErrorHandler
	}

	return a, nil
}
