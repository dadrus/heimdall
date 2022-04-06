package pipeline

import (
	"errors"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var (
	ErrNoDefaultAuthenticator = errors.New("no default authenticators configured")
	ErrNoDefaultAuthorizer    = errors.New("no default authorizer configured")
	ErrNoDefaultMutator       = errors.New("no default mutator configured")
	ErrNoDefaultErrorHandler  = errors.New("no default error handler configured")

	ErrAuthenticatorCreation = errors.New("failed to create authenticator")
	ErrAuthorizerCreation    = errors.New("failed to create authorizer")
	ErrMutatorCreation       = errors.New("failed to create mutator")
	ErrHydratorCreation      = errors.New("failed to create hydrator")
	ErrErrorHandlerCreation  = errors.New("failed to create error handler")
)

type HandlerFactory interface {
	CreateAuthenticator([]config.PipelineObjectReference) (handler.Authenticator, error)
	CreateAuthorizer(*config.PipelineObjectReference) (handler.Authorizer, error)
	CreateHydrator([]config.PipelineObjectReference) (handler.Hydrator, error)
	CreateMutator([]config.PipelineObjectReference) (handler.Mutator, error)
	CreateErrorHandler([]config.PipelineObjectReference) (handler.ErrorHandler, error)
}

func NewHandlerFactory(conf config.Configuration, logger zerolog.Logger) (HandlerFactory, error) {
	logger.Info().Msg("Loading pipeline definitions")

	repository, err := newHandlerPrototypeRepository(conf, logger)
	if err != nil {
		logger.Error().Err(err).Msg("Failed loading pipeline definitions")

		return nil, err
	}

	return &handlerFactory{
		r:  repository,
		dp: conf.Rules.Default,
	}, nil
}

type handlerFactory struct {
	r  *handlerPrototypeRepository
	dp config.Pipeline
}

func (hf *handlerFactory) CreateAuthenticator(pors []config.PipelineObjectReference) (handler.Authenticator, error) {
	var (
		refs []config.PipelineObjectReference
		list handler.CompositeAuthenticator
	)

	if len(pors) == 0 {
		if len(hf.dp.Authenticators) == 0 {
			return nil, errorchain.New(ErrAuthenticatorCreation).CausedBy(ErrNoDefaultAuthenticator)
		}

		refs = hf.dp.Authenticators
	} else {
		refs = pors
	}

	for _, ref := range refs {
		prototype, err := hf.r.Authenticator(ref.ID)
		if err != nil {
			return nil, errorchain.New(ErrAuthenticatorCreation).CausedBy(err)
		}

		if len(ref.Config) != 0 {
			authenticator, err := prototype.WithConfig(ref.Config)
			if err != nil {
				return nil, errorchain.New(ErrAuthenticatorCreation).CausedBy(err)
			}

			list = append(list, authenticator)
		} else {
			list = append(list, prototype)
		}
	}

	return list, nil
}

func (hf *handlerFactory) CreateAuthorizer(configured *config.PipelineObjectReference) (handler.Authorizer, error) {
	var ref *config.PipelineObjectReference

	if configured == nil {
		if hf.dp.Authorizer == nil {
			return nil, errorchain.New(ErrAuthorizerCreation).CausedBy(ErrNoDefaultAuthorizer)
		}

		ref = hf.dp.Authorizer
	} else {
		ref = configured
	}

	prototype, err := hf.r.Authorizer(ref.ID)
	if err != nil {
		return nil, errorchain.New(ErrAuthorizerCreation).CausedBy(err)
	}

	if len(ref.Config) != 0 {
		authorizer, err := prototype.WithConfig(ref.Config)
		if err != nil {
			return nil, errorchain.New(ErrAuthorizerCreation).CausedBy(err)
		}

		return authorizer, nil
	}

	return prototype, nil
}

func (hf *handlerFactory) CreateHydrator(configured []config.PipelineObjectReference) (handler.Hydrator, error) {
	var (
		refs []config.PipelineObjectReference
		list handler.CompositeHydrator
	)

	if len(configured) == 0 {
		if len(hf.dp.Hydrators) != 0 {
			refs = hf.dp.Hydrators
		}
	} else {
		refs = configured
	}

	for _, ref := range refs {
		prototype, err := hf.r.Hydrator(ref.ID)
		if err != nil {
			return nil, errorchain.New(ErrHydratorCreation).CausedBy(err)
		}

		if len(ref.Config) != 0 {
			hydrator, err := prototype.WithConfig(ref.Config)
			if err != nil {
				return nil, errorchain.New(ErrHydratorCreation).CausedBy(err)
			}

			list = append(list, hydrator)
		} else {
			list = append(list, prototype)
		}
	}

	return list, nil
}

func (hf *handlerFactory) CreateMutator(configured []config.PipelineObjectReference) (handler.Mutator, error) {
	var (
		refs []config.PipelineObjectReference
		list handler.CompositeMutator
	)

	if len(configured) == 0 {
		if len(hf.dp.Mutators) == 0 {
			return nil, errorchain.New(ErrMutatorCreation).CausedBy(ErrNoDefaultMutator)
		}

		refs = hf.dp.Mutators
	} else {
		refs = configured
	}

	for _, ref := range refs {
		prototype, err := hf.r.Mutator(ref.ID)
		if err != nil {
			return nil, errorchain.New(ErrMutatorCreation).CausedBy(err)
		}

		if len(ref.Config) != 0 {
			mutator, err := prototype.WithConfig(ref.Config)
			if err != nil {
				return nil, errorchain.New(ErrMutatorCreation).CausedBy(err)
			}

			list = append(list, mutator)
		} else {
			list = append(list, prototype)
		}
	}

	return list, nil
}

func (hf *handlerFactory) CreateErrorHandler(pors []config.PipelineObjectReference) (handler.ErrorHandler, error) {
	var (
		refs []config.PipelineObjectReference
		list handler.CompositeErrorHandler
	)

	if len(pors) == 0 {
		if len(hf.dp.ErrorHandlers) == 0 {
			return nil, errorchain.New(ErrErrorHandlerCreation).CausedBy(ErrNoDefaultErrorHandler)
		}

		refs = hf.dp.ErrorHandlers
	} else {
		refs = pors
	}

	for _, ref := range refs {
		prototype, err := hf.r.ErrorHandler(ref.ID)
		if err != nil {
			return nil, errorchain.New(ErrErrorHandlerCreation).CausedBy(err)
		}

		if len(ref.Config) != 0 {
			errorHandler, err := prototype.WithConfig(ref.Config)
			if err != nil {
				return nil, errorchain.New(ErrErrorHandlerCreation).CausedBy(err)
			}

			list = append(list, errorHandler)
		} else {
			list = append(list, prototype)
		}
	}

	return list, nil
}
