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

type HandlerFactory interface {
	CreateAuthenticator([]config.PipelineObjectReference) (handler.Authenticator, error)
	CreateAuthorizer(*config.PipelineObjectReference) (handler.Authorizer, error)
	CreateHydrator([]config.PipelineObjectReference) (handler.Hydrator, error)
	CreateMutator([]config.PipelineObjectReference) (handler.Mutator, error)
	CreateErrorHandler([]config.PipelineObjectReference) (handler.ErrorHandler, error)
}

func NewHandlerFactory(r HandlerRepository, c config.Configuration) (HandlerFactory, error) {
	return &handlerFactory{
		r:  r,
		dp: c.Rules.Default,
	}, nil
}

type handlerFactory struct {
	r  HandlerRepository
	dp config.Pipeline
}

func (hf *handlerFactory) CreateAuthenticator(configured []config.PipelineObjectReference) (handler.Authenticator, error) {
	var refs []config.PipelineObjectReference
	if len(configured) == 0 {
		if len(hf.dp.Authenticators) == 0 {
			return nil, errors.New("no default authenticators configured")
		}
		refs = hf.dp.Authenticators
	} else {
		refs = configured
	}

	var ans authenticators.CompositeAuthenticator
	for _, ref := range refs {
		a, err := hf.r.Authenticator(ref.Id)
		if err != nil {
			return nil, err
		}

		if len(ref.Config) != 0 {
			na, err := a.WithConfig(ref.Config)
			if err != nil {
				return nil, err
			}
			ans = append(ans, na)
		} else {
			ans = append(ans, a)
		}
	}

	return ans, nil
}

func (hf *handlerFactory) CreateAuthorizer(configured *config.PipelineObjectReference) (handler.Authorizer, error) {
	var ref *config.PipelineObjectReference
	if configured == nil {
		if hf.dp.Authorizer == nil {
			return nil, errors.New("no default authorizer configured")
		}
		ref = hf.dp.Authorizer
	} else {
		ref = configured
	}

	a, err := hf.r.Authorizer(ref.Id)
	if err == nil {
		if len(ref.Config) != 0 {
			return a.WithConfig(ref.Config)
		}
		return a, nil
	}
	return a, err
}
func (hf *handlerFactory) CreateHydrator(configured []config.PipelineObjectReference) (handler.Hydrator, error) {
	var refs []config.PipelineObjectReference
	if len(configured) == 0 {
		if len(hf.dp.Hydrators) != 0 {
			refs = hf.dp.Hydrators
		}
	} else {
		refs = configured
	}

	var hs hydrators.CompositeHydrator
	for _, ref := range refs {
		h, err := hf.r.Hydrator(ref.Id)
		if err != nil {
			return nil, err
		}

		if len(ref.Config) != 0 {
			nh, err := h.WithConfig(ref.Config)
			if err != nil {
				return nil, err
			}
			hs = append(hs, nh)
		} else {
			hs = append(hs, h)
		}
	}

	return hs, nil
}
func (hf *handlerFactory) CreateMutator(configured []config.PipelineObjectReference) (handler.Mutator, error) {
	var refs []config.PipelineObjectReference
	if len(configured) == 0 {
		if len(hf.dp.Mutators) == 0 {
			return nil, errors.New("no default mutators configured")
		}
		refs = hf.dp.Mutators
	} else {
		refs = configured
	}

	var ms mutators.CompositeMutator
	for _, ref := range refs {
		m, err := hf.r.Mutator(ref.Id)
		if err != nil {
			return nil, err
		}

		if len(ref.Config) != 0 {
			nm, err := m.WithConfig(ref.Config)
			if err != nil {
				return nil, err
			}
			ms = append(ms, nm)
		} else {
			ms = append(ms, m)
		}
	}

	return ms, nil
}
func (hf *handlerFactory) CreateErrorHandler(configured []config.PipelineObjectReference) (handler.ErrorHandler, error) {
	var refs []config.PipelineObjectReference
	if len(configured) == 0 {
		if len(hf.dp.ErrorHandlers) == 0 {
			return nil, errors.New("no default error handler configured")
		}
		refs = hf.dp.ErrorHandlers
	} else {
		refs = configured
	}

	var ehs error_handlers.CompositeErrorHandler
	for _, ref := range refs {
		eh, err := hf.r.ErrorHandler(ref.Id)
		if err != nil {
			return nil, err
		}

		if len(ref.Config) != 0 {
			neh, err := eh.WithConfig(ref.Config)
			if err != nil {
				return nil, err
			}
			ehs = append(ehs, neh)
		} else {
			ehs = append(ehs, eh)
		}
	}

	return ehs, nil
}
