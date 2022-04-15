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

var (
	ErrAuthenticatorCreation = errors.New("failed to create authenticator")
	ErrAuthorizerCreation    = errors.New("failed to create authorizer")
	ErrMutatorCreation       = errors.New("failed to create mutator")
	ErrHydratorCreation      = errors.New("failed to create hydrator")
	ErrErrorHandlerCreation  = errors.New("failed to create error handler")
)

type HandlerFactory interface {
	CreateAuthenticator(id string, conf any) (authenticators.Authenticator, error)
	CreateAuthorizer(id string, conf any) (authorizers.Authorizer, error)
	CreateHydrator(id string, conf any) (hydrators.Hydrator, error)
	CreateMutator(id string, conf any) (mutators.Mutator, error)
	CreateErrorHandler(id string, conf any) (errorhandlers.ErrorHandler, error)
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

func (hf *handlerFactory) CreateAuthenticator(id string, conf any) (authenticators.Authenticator, error) {
	prototype, err := hf.r.Authenticator(id)
	if err != nil {
		return nil, errorchain.New(ErrAuthenticatorCreation).CausedBy(err)
	}

	if conf != nil {
		mConf, ok := conf.(map[any]any)
		if !ok {
			return nil, errorchain.NewWithMessage(ErrAuthenticatorCreation,
				"Could not convert config to the expected type")
		}

		authenticator, err := prototype.WithConfig(mConf)
		if err != nil {
			return nil, errorchain.New(ErrAuthenticatorCreation).CausedBy(err)
		}

		return authenticator, nil
	}

	return prototype, nil
}

func (hf *handlerFactory) CreateAuthorizer(id string, conf any) (authorizers.Authorizer, error) {
	prototype, err := hf.r.Authorizer(id)
	if err != nil {
		return nil, errorchain.New(ErrAuthorizerCreation).CausedBy(err)
	}

	if conf != nil {
		mConf, ok := conf.(map[any]any)
		if !ok {
			return nil, errorchain.NewWithMessage(ErrAuthenticatorCreation,
				"Could not convert config to the expected type")
		}

		authorizer, err := prototype.WithConfig(mConf)
		if err != nil {
			return nil, errorchain.New(ErrAuthorizerCreation).CausedBy(err)
		}

		return authorizer, nil
	}

	return prototype, nil
}

func (hf *handlerFactory) CreateHydrator(id string, conf any) (hydrators.Hydrator, error) {
	prototype, err := hf.r.Hydrator(id)
	if err != nil {
		return nil, errorchain.New(ErrHydratorCreation).CausedBy(err)
	}

	if conf != nil {
		mConf, ok := conf.(map[any]any)
		if !ok {
			return nil, errorchain.NewWithMessage(ErrAuthenticatorCreation,
				"Could not convert config to the expected type")
		}

		hydrator, err := prototype.WithConfig(mConf)
		if err != nil {
			return nil, errorchain.New(ErrHydratorCreation).CausedBy(err)
		}

		return hydrator, nil
	}

	return prototype, nil
}

func (hf *handlerFactory) CreateMutator(id string, conf any) (mutators.Mutator, error) {
	prototype, err := hf.r.Mutator(id)
	if err != nil {
		return nil, errorchain.New(ErrMutatorCreation).CausedBy(err)
	}

	if conf != nil {
		mConf, ok := conf.(map[any]any)
		if !ok {
			return nil, errorchain.NewWithMessage(ErrAuthenticatorCreation,
				"Could not convert config to the expected type")
		}

		mutator, err := prototype.WithConfig(mConf)
		if err != nil {
			return nil, errorchain.New(ErrMutatorCreation).CausedBy(err)
		}

		return mutator, nil
	}

	return prototype, nil
}

func (hf *handlerFactory) CreateErrorHandler(id string, conf any) (errorhandlers.ErrorHandler, error) {
	prototype, err := hf.r.ErrorHandler(id)
	if err != nil {
		return nil, errorchain.New(ErrErrorHandlerCreation).CausedBy(err)
	}

	if conf != nil {
		mConf, ok := conf.(map[any]any)
		if !ok {
			return nil, errorchain.NewWithMessage(ErrAuthenticatorCreation,
				"Could not convert config to the expected type")
		}

		errorHandler, err := prototype.WithConfig(mConf)
		if err != nil {
			return nil, errorchain.New(ErrErrorHandlerCreation).CausedBy(err)
		}

		return errorHandler, nil
	}

	return prototype, nil
}
