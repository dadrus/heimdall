package mechanisms

import (
	"errors"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/authorizers"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/errorhandlers"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/hydrators"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/mutators"
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
	CreateAuthenticator(id string, conf config.MechanismConfig) (authenticators.Authenticator, error)
	CreateAuthorizer(id string, conf config.MechanismConfig) (authorizers.Authorizer, error)
	CreateHydrator(id string, conf config.MechanismConfig) (hydrators.Hydrator, error)
	CreateMutator(id string, conf config.MechanismConfig) (mutators.Mutator, error)
	CreateErrorHandler(id string, conf config.MechanismConfig) (errorhandlers.ErrorHandler, error)
}

func NewHandlerFactory(conf config.Configuration, logger zerolog.Logger) (HandlerFactory, error) {
	logger.Info().Msg("Loading pipeline definitions")

	repository, err := newHandlerPrototypeRepository(conf, logger)
	if err != nil {
		logger.Error().Err(err).Msg("Failed loading pipeline definitions")

		return nil, err
	}

	return &handlerFactory{r: repository}, nil
}

type handlerFactory struct {
	r *handlerPrototypeRepository
}

func (hf *handlerFactory) CreateAuthenticator(id string, conf config.MechanismConfig) (
	authenticators.Authenticator, error,
) {
	prototype, err := hf.r.Authenticator(id)
	if err != nil {
		return nil, errorchain.New(ErrAuthenticatorCreation).CausedBy(err)
	}

	if conf != nil {
		authenticator, err := prototype.WithConfig(conf)
		if err != nil {
			return nil, errorchain.New(ErrAuthenticatorCreation).CausedBy(err)
		}

		return authenticator, nil
	}

	return prototype, nil
}

func (hf *handlerFactory) CreateAuthorizer(id string, conf config.MechanismConfig) (
	authorizers.Authorizer, error,
) {
	prototype, err := hf.r.Authorizer(id)
	if err != nil {
		return nil, errorchain.New(ErrAuthorizerCreation).CausedBy(err)
	}

	if conf != nil {
		authorizer, err := prototype.WithConfig(conf)
		if err != nil {
			return nil, errorchain.New(ErrAuthorizerCreation).CausedBy(err)
		}

		return authorizer, nil
	}

	return prototype, nil
}

func (hf *handlerFactory) CreateHydrator(id string, conf config.MechanismConfig) (
	hydrators.Hydrator, error,
) {
	prototype, err := hf.r.Hydrator(id)
	if err != nil {
		return nil, errorchain.New(ErrHydratorCreation).CausedBy(err)
	}

	if conf != nil {
		hydrator, err := prototype.WithConfig(conf)
		if err != nil {
			return nil, errorchain.New(ErrHydratorCreation).CausedBy(err)
		}

		return hydrator, nil
	}

	return prototype, nil
}

func (hf *handlerFactory) CreateMutator(id string, conf config.MechanismConfig) (
	mutators.Mutator, error,
) {
	prototype, err := hf.r.Mutator(id)
	if err != nil {
		return nil, errorchain.New(ErrMutatorCreation).CausedBy(err)
	}

	if conf != nil {
		mutator, err := prototype.WithConfig(conf)
		if err != nil {
			return nil, errorchain.New(ErrMutatorCreation).CausedBy(err)
		}

		return mutator, nil
	}

	return prototype, nil
}

func (hf *handlerFactory) CreateErrorHandler(id string, conf config.MechanismConfig) (
	errorhandlers.ErrorHandler, error,
) {
	prototype, err := hf.r.ErrorHandler(id)
	if err != nil {
		return nil, errorchain.New(ErrErrorHandlerCreation).CausedBy(err)
	}

	if conf != nil {
		errorHandler, err := prototype.WithConfig(conf)
		if err != nil {
			return nil, errorchain.New(ErrErrorHandlerCreation).CausedBy(err)
		}

		return errorHandler, nil
	}

	return prototype, nil
}
