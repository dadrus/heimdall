package mechanisms

import (
	"errors"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/authorizers"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/contextualizers"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/errorhandlers"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/mutators"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var (
	ErrAuthenticatorCreation  = errors.New("failed to create authenticator")
	ErrAuthorizerCreation     = errors.New("failed to create authorizer")
	ErrMutatorCreation        = errors.New("failed to create mutator")
	ErrContextualizerCreation = errors.New("failed to create contextualizer")
	ErrErrorHandlerCreation   = errors.New("failed to create error handler")
)

type Factory interface {
	CreateAuthenticator(id string, conf config.MechanismConfig) (authenticators.Authenticator, error)
	CreateAuthorizer(id string, conf config.MechanismConfig) (authorizers.Authorizer, error)
	CreateContextualizer(id string, conf config.MechanismConfig) (contextualizers.Contextualizer, error)
	CreateMutator(id string, conf config.MechanismConfig) (mutators.Mutator, error)
	CreateErrorHandler(id string, conf config.MechanismConfig) (errorhandlers.ErrorHandler, error)
}

func NewFactory(conf *config.Configuration, logger zerolog.Logger) (Factory, error) {
	logger.Info().Msg("Loading pipeline definitions")

	repository, err := newPrototypeRepository(conf, logger)
	if err != nil {
		logger.Error().Err(err).Msg("Failed loading pipeline definitions")

		return nil, err
	}

	return &mechanismsFactory{r: repository}, nil
}

type mechanismsFactory struct {
	r *prototypeRepository
}

func (hf *mechanismsFactory) CreateAuthenticator(id string, conf config.MechanismConfig) (
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

func (hf *mechanismsFactory) CreateAuthorizer(id string, conf config.MechanismConfig) (
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

func (hf *mechanismsFactory) CreateContextualizer(id string, conf config.MechanismConfig) (
	contextualizers.Contextualizer, error,
) {
	prototype, err := hf.r.Hydrator(id)
	if err != nil {
		return nil, errorchain.New(ErrContextualizerCreation).CausedBy(err)
	}

	if conf != nil {
		contextualizer, err := prototype.WithConfig(conf)
		if err != nil {
			return nil, errorchain.New(ErrContextualizerCreation).CausedBy(err)
		}

		return contextualizer, nil
	}

	return prototype, nil
}

func (hf *mechanismsFactory) CreateMutator(id string, conf config.MechanismConfig) (
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

func (hf *mechanismsFactory) CreateErrorHandler(id string, conf config.MechanismConfig) (
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
