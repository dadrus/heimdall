package pipeline

import (
	"errors"

	"github.com/rs/zerolog"

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
	ErrUnsupportedPipelineObjectType = errors.New("pipeline object type unsupported")
	ErrNoSuchPipelineObject          = errors.New("pipeline object not found")
)

func newHandlerPrototypeRepository(
	conf config.Configuration,
	logger zerolog.Logger,
) (*handlerPrototypeRepository, error) {
	logger.Debug().Msg("Loading definitions for authenticators")

	authenticatorMap, err := createPipelineObjects(conf.Pipeline.Authenticators, logger, newAuthenticator)
	if err != nil {
		logger.Error().Err(err).Msg("Failed loading authenticators definitions")

		return nil, err
	}

	logger.Debug().Msg("Loading definitions for authorizers")

	authorizerMap, err := createPipelineObjects(conf.Pipeline.Authorizers, logger, newAuthorizer)
	if err != nil {
		logger.Error().Err(err).Msg("Failed loading authorizers definitions")

		return nil, err
	}

	logger.Debug().Msg("Loading definitions for hydrators")

	hydratorMap, err := createPipelineObjects(conf.Pipeline.Hydrators, logger, newHydrator)
	if err != nil {
		logger.Error().Err(err).Msg("Failed loading hydrators definitions")

		return nil, err
	}

	logger.Debug().Msg("Loading definitions for mutators")

	mutatorMap, err := createPipelineObjects(conf.Pipeline.Mutators, logger, newMutator)
	if err != nil {
		logger.Error().Err(err).Msg("Failed loading mutators definitions")

		return nil, err
	}

	logger.Debug().Msg("Loading definitions for error handler")

	ehMap, err := createPipelineObjects(conf.Pipeline.ErrorHandlers, logger, newErrorHandler)
	if err != nil {
		logger.Error().Err(err).Msg("Failed loading error handler definitions")

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
	logger zerolog.Logger,
	create func(obj config.PipelineObject) (T, error),
) (map[string]T, error) {
	objects := make(map[string]T)

	for _, pe := range pObjects {
		logger.Debug().Str("id", pe.ID).Str("type", string(pe.Type)).Msg("Loading pipeline definition")

		if r, err := create(pe); err == nil {
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
		authenticator, err = authenticators.NewAnonymousAuthenticator(obj.Config)
	case config.POTUnauthorized:
		authenticator, err = authenticators.NewUnauthorizedAuthenticator(), nil
	case config.POTAuthenticationData:
		authenticator, err = authenticators.NewAuthenticationDataAuthenticator(obj.Config)
	case config.POTOAuth2Introspection:
		authenticator, err = authenticators.NewOAuth2IntrospectionAuthenticator(obj.Config)
	case config.POTJwt:
		authenticator, err = authenticators.NewJwtAuthenticator(obj.Config)
	default:
		err = errorchain.NewWithMessagef(ErrUnsupportedPipelineObjectType,
			"authenticator type \"%s\" unknown", string(obj.Type))
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
		authorizer, err = authorizers.NewRemoteAuthorizer(obj.Config)
	default:
		err = errorchain.NewWithMessagef(ErrUnsupportedPipelineObjectType, "authorizer type '%s' unknown", string(obj.Type))
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
		hydrator, err = hydrators.NewDefaultHydrator(obj.Config)
	default:
		err = errorchain.NewWithMessagef(ErrUnsupportedPipelineObjectType, "hydrator type '%s' unknown", string(obj.Type))
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
		mutator, err = mutators.NewJWTMutator(obj.Config)
	case config.POTHeader:
		mutator, err = mutators.NewHeaderMutator(obj.Config)
	case config.POTCookie:
		mutator, err = mutators.NewCookieMutator(obj.Config)
	default:
		err = errorchain.NewWithMessagef(ErrUnsupportedPipelineObjectType, "mutator type '%s' unknown", string(obj.Type))
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
		handler, err = errorhandlers.NewJsonErrorHandler(obj.Config)
	case config.POTRedirect:
		handler, err = errorhandlers.NewRedirectErrorHandler(obj.Config)
	default:
		err = errorchain.NewWithMessagef(ErrUnsupportedPipelineObjectType,
			"error handler type '%s' unknown", string(obj.Type))
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
		return nil, errorchain.NewWithMessagef(ErrNoSuchPipelineObject, "no authenticator prototype for id='%s' found", id)
	}

	return authenticator, nil
}

func (r *handlerPrototypeRepository) Authorizer(id string) (handler.Authorizer, error) {
	authorizer, ok := r.authorizers[id]
	if !ok {
		return nil, errorchain.NewWithMessagef(ErrNoSuchPipelineObject, "no authorizer prototype for id='%s' found", id)
	}

	return authorizer, nil
}

func (r *handlerPrototypeRepository) Hydrator(id string) (handler.Hydrator, error) {
	hydrator, ok := r.hydrators[id]
	if !ok {
		return nil, errorchain.NewWithMessagef(ErrNoSuchPipelineObject, "no hydrator prototype for id='%s' found", id)
	}

	return hydrator, nil
}

func (r *handlerPrototypeRepository) Mutator(id string) (handler.Mutator, error) {
	mutator, ok := r.mutators[id]
	if !ok {
		return nil, errorchain.NewWithMessagef(ErrNoSuchPipelineObject, "no mutator prototype for id='%s' found", id)
	}

	return mutator, nil
}

func (r *handlerPrototypeRepository) ErrorHandler(id string) (handler.ErrorHandler, error) {
	errorHandler, ok := r.errorHandlers[id]
	if !ok {
		return nil, errorchain.NewWithMessagef(ErrNoSuchPipelineObject, "no error handler prototype for id='%s' found", id)
	}

	return errorHandler, nil
}
