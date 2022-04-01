package pipeline

import (
	"errors"
	"fmt"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
	"github.com/dadrus/heimdall/internal/pipeline/handler/authenticators"
	"github.com/dadrus/heimdall/internal/pipeline/handler/authorizers"
	"github.com/dadrus/heimdall/internal/pipeline/handler/errorhandlers"
	"github.com/dadrus/heimdall/internal/pipeline/handler/hydrators"
	"github.com/dadrus/heimdall/internal/pipeline/handler/mutators"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var (
	ErrUnknownAuthenticatorType = errors.New("unknown authenticator type")
	ErrUnknownAuthorizerType    = errors.New("unknown authorizer type")
	ErrUnknownHydratorType      = errors.New("unknown hydrator type")
	ErrUnknownMutatorType       = errors.New("unknown mutator type")
	ErrUnknownErrorHandlerType  = errors.New("unknown error handler type")
)

type noSuchObjectError struct {
	message string
}

func (e *noSuchObjectError) Error() string { return e.message }

type (
	NoSuchAuthenticatorError = noSuchObjectError
	NoSuchAuthorizerError    = noSuchObjectError
	NoSuchHydratorError      = noSuchObjectError
	NoSuchMutatorError       = noSuchObjectError
	NoSuchErrorHandlerError  = noSuchObjectError
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
			objects[pe.ID] = r
		} else {
			return nil, err
		}
	}

	return objects, nil
}

func newAuthenticator(obj config.PipelineObject) (handler.Authenticator, error) {
	var (
		err           error
		authenticator handler.Authenticator
	)

	switch obj.Type {
	case config.POTNoop:
		authenticator, err = authenticators.NewNoopAuthenticator(), nil
	case config.POTAnonymous:
		authenticator, err = authenticators.NewAnonymousAuthenticatorFromYAML(obj.Config)
	case config.POTUnauthorized:
		authenticator, err = authenticators.NewUnauthorizedAuthenticator(), nil
	case config.POTAuthenticationData:
		authenticator, err = authenticators.NewAuthenticationDataAuthenticatorFromYAML(obj.Config)
	case config.POTOAuth2Introspection:
		authenticator, err = authenticators.NewOAuth2IntrospectionAuthenticatorFromYAML(obj.Config)
	case config.POTJwt:
		authenticator, err = authenticators.NewJwtAuthenticatorFromYAML(obj.Config)
	default:
		err = ErrUnknownAuthenticatorType
	}

	if err != nil {
		return nil, errorchain.New(ErrAuthenticatorCreation).CausedBy(err)
	}

	return authenticator, nil
}

func newAuthorizer(obj config.PipelineObject) (handler.Authorizer, error) {
	var (
		err        error
		authorizer handler.Authorizer
	)

	switch obj.Type {
	case config.POTAllow:
		authorizer, err = authorizers.NewAllowAuthorizer(), nil
	case config.POTDeny:
		authorizer, err = authorizers.NewDenyAuthorizer(), nil
	case config.POTRemote:
		authorizer, err = authorizers.NewRemoteAuthorizerFromJSON(obj.Config)
	default:
		err = ErrUnknownAuthorizerType
	}

	if err != nil {
		return nil, errorchain.New(ErrAuthorizerCreation).CausedBy(err)
	}

	return authorizer, nil
}

func newHydrator(obj config.PipelineObject) (handler.Hydrator, error) {
	var (
		err      error
		hydrator handler.Hydrator
	)

	switch obj.Type {
	case config.POTDefault:
		hydrator, err = hydrators.NewDefaultHydratorFromJSON(obj.Config)
	default:
		err = ErrUnknownHydratorType
	}

	if err != nil {
		return nil, errorchain.New(ErrHydratorCreation).CausedBy(err)
	}

	return hydrator, nil
}

func newMutator(obj config.PipelineObject) (handler.Mutator, error) {
	var (
		err     error
		mutator handler.Mutator
	)

	switch obj.Type {
	case config.POTJwt:
		mutator, err = mutators.NewJWTMutatorFromJSON(obj.Config)
	case config.POTHeader:
		mutator, err = mutators.NewHeaderMutatorFromJSON(obj.Config)
	case config.POTCookie:
		mutator, err = mutators.NewCookieMutatorFromJSON(obj.Config)
	default:
		err = ErrUnknownMutatorType
	}

	if err != nil {
		return nil, errorchain.New(ErrMutatorCreation).CausedBy(err)
	}

	return mutator, nil
}

func newErrorHandler(obj config.PipelineObject) (handler.ErrorHandler, error) {
	var (
		err     error
		handler handler.ErrorHandler
	)

	switch obj.Type {
	case config.POTJson:
		handler, err = errorhandlers.NewJsonErrorHandlerFromYAML(obj.Config)
	case config.POTRedirect:
		handler, err = errorhandlers.NewRedirectErrorHandlerFromJSON(obj.Config)
	default:
		err = ErrUnknownErrorHandlerType
	}

	if err != nil {
		return nil, errorchain.New(ErrErrorHandlerCreation).CausedBy(err)
	}

	return handler, nil
}

type handlerPrototypeRepository struct {
	authenticators map[string]handler.Authenticator
	authorizers    map[string]handler.Authorizer
	hydrators      map[string]handler.Hydrator
	mutators       map[string]handler.Mutator
	errorHandlers  map[string]handler.ErrorHandler
}

func (r *handlerPrototypeRepository) Authenticator(id string) (handler.Authenticator, error) {
	authenticator, ok := r.authenticators[id]
	if !ok {
		return nil, &NoSuchAuthenticatorError{
			message: fmt.Sprintf("no authenticator for %s found", id),
		}
	}

	return authenticator, nil
}

func (r *handlerPrototypeRepository) Authorizer(id string) (handler.Authorizer, error) {
	authorizer, ok := r.authorizers[id]
	if !ok {
		return nil, &NoSuchAuthorizerError{
			message: fmt.Sprintf("no authorizer for %s found", id),
		}
	}

	return authorizer, nil
}

func (r *handlerPrototypeRepository) Hydrator(id string) (handler.Hydrator, error) {
	hydrator, ok := r.hydrators[id]
	if !ok {
		return nil, &NoSuchHydratorError{
			message: fmt.Sprintf("no hydrator for %s found", id),
		}
	}

	return hydrator, nil
}

func (r *handlerPrototypeRepository) Mutator(id string) (handler.Mutator, error) {
	mutator, ok := r.mutators[id]
	if !ok {
		return nil, &NoSuchMutatorError{
			message: fmt.Sprintf("no mutator for %s found", id),
		}
	}

	return mutator, nil
}

func (r *handlerPrototypeRepository) ErrorHandler(id string) (handler.ErrorHandler, error) {
	errorHandler, ok := r.errorHandlers[id]
	if !ok {
		return nil, &NoSuchErrorHandlerError{
			message: fmt.Sprintf("no error handler for %s found", id),
		}
	}

	return errorHandler, nil
}
