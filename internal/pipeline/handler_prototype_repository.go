package pipeline

import (
	"errors"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/pipeline/authenticators"
	"github.com/dadrus/heimdall/internal/pipeline/authorizers"
	"github.com/dadrus/heimdall/internal/pipeline/errorhandlers"
	"github.com/dadrus/heimdall/internal/pipeline/hydrators"
	"github.com/dadrus/heimdall/internal/pipeline/mutators"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var ErrNoSuchPipelineObject = errors.New("pipeline object not found")

func newHandlerPrototypeRepository(
	conf config.Configuration,
	logger zerolog.Logger,
) (*handlerPrototypeRepository, error) {
	logger.Debug().Msg("Loading definitions for authenticators")

	authenticatorMap, err := createPipelineObjects(conf.Pipeline.Authenticators, logger,
		authenticators.CreateAuthenticatorPrototype)
	if err != nil {
		logger.Error().Err(err).Msg("Failed loading authenticators definitions")

		return nil, err
	}

	logger.Debug().Msg("Loading definitions for authorizers")

	authorizerMap, err := createPipelineObjects(conf.Pipeline.Authorizers, logger,
		authorizers.CreateAuthorizerPrototype)
	if err != nil {
		logger.Error().Err(err).Msg("Failed loading authorizers definitions")

		return nil, err
	}

	logger.Debug().Msg("Loading definitions for hydrators")

	hydratorMap, err := createPipelineObjects(conf.Pipeline.Hydrators, logger,
		hydrators.CreateHydratorPrototype)
	if err != nil {
		logger.Error().Err(err).Msg("Failed loading hydrators definitions")

		return nil, err
	}

	logger.Debug().Msg("Loading definitions for mutators")

	mutatorMap, err := createPipelineObjects(conf.Pipeline.Mutators, logger,
		mutators.CreateMutatorPrototype)
	if err != nil {
		logger.Error().Err(err).Msg("Failed loading mutators definitions")

		return nil, err
	}

	logger.Debug().Msg("Loading definitions for error handler")

	ehMap, err := createPipelineObjects(conf.Pipeline.ErrorHandlers, logger,
		errorhandlers.CreateErrorHandlerPrototype)
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
	create func(t config.PipelineObjectType, c map[string]any) (T, error),
) (map[string]T, error) {
	objects := make(map[string]T)

	for _, pe := range pObjects {
		logger.Debug().Str("id", pe.ID).Str("type", string(pe.Type)).Msg("Loading pipeline definition")

		if r, err := create(pe.Type, pe.Config); err == nil {
			objects[pe.ID] = r
		} else {
			return nil, err
		}
	}

	return objects, nil
}

type handlerPrototypeRepository struct {
	authenticators map[string]authenticators.Authenticator
	authorizers    map[string]authorizers.Authorizer
	hydrators      map[string]hydrators.Hydrator
	mutators       map[string]mutators.Mutator
	errorHandlers  map[string]errorhandlers.ErrorHandler
}

func (r *handlerPrototypeRepository) Authenticator(id string) (authenticators.Authenticator, error) {
	authenticator, ok := r.authenticators[id]
	if !ok {
		return nil, errorchain.NewWithMessagef(ErrNoSuchPipelineObject, "no authenticator prototype for id='%s' found", id)
	}

	return authenticator, nil
}

func (r *handlerPrototypeRepository) Authorizer(id string) (authorizers.Authorizer, error) {
	authorizer, ok := r.authorizers[id]
	if !ok {
		return nil, errorchain.NewWithMessagef(ErrNoSuchPipelineObject, "no authorizer prototype for id='%s' found", id)
	}

	return authorizer, nil
}

func (r *handlerPrototypeRepository) Hydrator(id string) (hydrators.Hydrator, error) {
	hydrator, ok := r.hydrators[id]
	if !ok {
		return nil, errorchain.NewWithMessagef(ErrNoSuchPipelineObject, "no hydrator prototype for id='%s' found", id)
	}

	return hydrator, nil
}

func (r *handlerPrototypeRepository) Mutator(id string) (mutators.Mutator, error) {
	mutator, ok := r.mutators[id]
	if !ok {
		return nil, errorchain.NewWithMessagef(ErrNoSuchPipelineObject, "no mutator prototype for id='%s' found", id)
	}

	return mutator, nil
}

func (r *handlerPrototypeRepository) ErrorHandler(id string) (errorhandlers.ErrorHandler, error) {
	errorHandler, ok := r.errorHandlers[id]
	if !ok {
		return nil, errorchain.NewWithMessagef(ErrNoSuchPipelineObject, "no error handler prototype for id='%s' found", id)
	}

	return errorHandler, nil
}
