package pipeline

import (
	"errors"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
	"github.com/dadrus/heimdall/internal/pipeline/handler/authenticators"
	"github.com/dadrus/heimdall/internal/pipeline/handler/error_handlers"
	"github.com/dadrus/heimdall/internal/pipeline/handler/hydrators"
	"github.com/dadrus/heimdall/internal/pipeline/handler/mutators"
)

var (
	ErrNoDefaultAuthenticator = errors.New("no default authenticators configured")
	ErrNoDefaultAuthorizer    = errors.New("no default authorizer configured")
	ErrNoDefaultMutator       = errors.New("no default mutator configured")
	ErrNoDefaultErrorHandler  = errors.New("no default error handler configured")
)

type HandlerFactory interface {
	CreateAuthenticator([]config.PipelineObjectReference) (handler.Authenticator, error)
	CreateAuthorizer(*config.PipelineObjectReference) (handler.Authorizer, error)
	CreateHydrator([]config.PipelineObjectReference) (handler.Hydrator, error)
	CreateMutator([]config.PipelineObjectReference) (handler.Mutator, error)
	CreateErrorHandler([]config.PipelineObjectReference) (handler.ErrorHandler, error)
}

func NewHandlerFactory(conf config.Configuration) (HandlerFactory, error) {
	repository, err := newHandlerPrototypeRepository(conf)
	if err != nil {
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
		list authenticators.CompositeAuthenticator
	)

	if len(pors) == 0 {
		if len(hf.dp.Authenticators) == 0 {
			return nil, ErrNoDefaultAuthenticator
		}

		refs = hf.dp.Authenticators
	} else {
		refs = pors
	}

	for _, ref := range refs {
		prototype, err := hf.r.Authenticator(ref.Id)
		if err != nil {
			return nil, err
		}

		if len(ref.Config) != 0 {
			authenticator, err := prototype.WithConfig(ref.Config)
			if err != nil {
				return nil, err
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
			return nil, ErrNoDefaultAuthorizer
		}

		ref = hf.dp.Authorizer
	} else {
		ref = configured
	}

	prototype, err := hf.r.Authorizer(ref.Id)
	if err == nil {
		if len(ref.Config) != 0 {
			return prototype.WithConfig(ref.Config)
		}

		return prototype, nil
	}

	return prototype, err
}

func (hf *handlerFactory) CreateHydrator(configured []config.PipelineObjectReference) (handler.Hydrator, error) {
	var (
		refs []config.PipelineObjectReference
		list hydrators.CompositeHydrator
	)

	if len(configured) == 0 {
		if len(hf.dp.Hydrators) != 0 {
			refs = hf.dp.Hydrators
		}
	} else {
		refs = configured
	}

	for _, ref := range refs {
		prototype, err := hf.r.Hydrator(ref.Id)
		if err != nil {
			return nil, err
		}

		if len(ref.Config) != 0 {
			hydrator, err := prototype.WithConfig(ref.Config)
			if err != nil {
				return nil, err
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
		list mutators.CompositeMutator
	)

	if len(configured) == 0 {
		if len(hf.dp.Mutators) == 0 {
			return nil, ErrNoDefaultMutator
		}

		refs = hf.dp.Mutators
	} else {
		refs = configured
	}

	for _, ref := range refs {
		prototype, err := hf.r.Mutator(ref.Id)
		if err != nil {
			return nil, err
		}

		if len(ref.Config) != 0 {
			mutator, err := prototype.WithConfig(ref.Config)
			if err != nil {
				return nil, err
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
		list error_handlers.CompositeErrorHandler
	)

	if len(pors) == 0 {
		if len(hf.dp.ErrorHandlers) == 0 {
			return nil, ErrNoDefaultErrorHandler
		}

		refs = hf.dp.ErrorHandlers
	} else {
		refs = pors
	}

	for _, ref := range refs {
		prototype, err := hf.r.ErrorHandler(ref.Id)
		if err != nil {
			return nil, err
		}

		if len(ref.Config) != 0 {
			errorHandler, err := prototype.WithConfig(ref.Config)
			if err != nil {
				return nil, err
			}

			list = append(list, errorHandler)
		} else {
			list = append(list, prototype)
		}
	}

	return list, nil
}
