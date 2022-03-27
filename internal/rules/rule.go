package rules

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/pipeline/interfaces"
)

type Rule interface {
	Id() string
	Execute(ctx context.Context, ads interfaces.AuthDataSource) (*heimdall.SubjectContext, error)
	Matches(requestUrl *url.URL) bool
}

func createAuthenticator(pr pipeline.Repository, configuredAuthenticators []config.PipelineObjectReference, defaultAuthenticators []config.PipelineObjectReference) (pipeline.Authenticator, error) {
	var refs []config.PipelineObjectReference
	if len(configuredAuthenticators) == 0 {
		if len(defaultAuthenticators) == 0 {
			return nil, errors.New("no default authenticators configured")
		}
		refs = defaultAuthenticators
	} else {
		refs = configuredAuthenticators
	}

	var ans []pipeline.Authenticator

	for _, ref := range refs {
		a, err := pr.Authenticator(ref.Id)
		if err != nil {
			return nil, err
		}
		na, err := a.WithConfig(ref.Config)
		if err != nil {
			return nil, err
		}
		ans = append(ans, na)
	}

	return &compositeAuthenticator{
		ans: ans,
	}, nil
}

func createAuthorizer(pr pipeline.Repository, configuredAuthorizer *config.PipelineObjectReference, defaultAuthorizer *config.PipelineObjectReference) (pipeline.Authorizer, error) {
	var ref *config.PipelineObjectReference
	if configuredAuthorizer == nil {
		if defaultAuthorizer == nil {
			return nil, errors.New("no default authorizer configured")
		}
		ref = defaultAuthorizer
	} else {
		ref = configuredAuthorizer
	}

	a, err := pr.Authorizer(ref.Id)
	if err == nil {
		return a.WithConfig(ref.Config)
	}
	return a, err
}

func createHydrator(pr pipeline.Repository, configuredHydrators []config.PipelineObjectReference, defaultHydrators []config.PipelineObjectReference) (pipeline.Hydrator, error) {
	var refs []config.PipelineObjectReference
	if len(configuredHydrators) == 0 {
		if len(defaultHydrators) != 0 {
			refs = defaultHydrators
		}
	} else {
		refs = configuredHydrators
	}

	var hs []pipeline.Hydrator
	for _, ref := range refs {
		h, err := pr.Hydrator(ref.Id)
		if err != nil {
			return nil, err
		}
		nh, err := h.WithConfig(ref.Config)
		if err != nil {
			return nil, err
		}
		hs = append(hs, nh)
	}

	return &compositeHydrator{
		hs: hs,
	}, nil
}

func createMutator(pr pipeline.Repository, configuredMutators []config.PipelineObjectReference, defaultMutators []config.PipelineObjectReference) (pipeline.Mutator, error) {
	var refs []config.PipelineObjectReference
	if len(configuredMutators) == 0 {
		if len(defaultMutators) == 0 {
			return nil, errors.New("no default mutators configured")
		}
		refs = defaultMutators
	} else {
		refs = configuredMutators
	}

	var ms []pipeline.Mutator
	for _, ref := range refs {
		m, err := pr.Mutator(ref.Id)
		if err != nil {
			return nil, err
		}
		nm, err := m.WithConfig(ref.Config)
		if err != nil {
			return nil, err
		}
		ms = append(ms, nm)
	}

	return &compositeMutator{
		ms: ms,
	}, nil
}

func createErrorHandler(pr pipeline.Repository, configuredErrorHandlers []config.PipelineObjectReference, defaultErrorHandlers []config.PipelineObjectReference) (pipeline.ErrorHandler, error) {
	var refs []config.PipelineObjectReference
	if len(configuredErrorHandlers) == 0 {
		if len(defaultErrorHandlers) == 0 {
			return nil, errors.New("no default error handler configured")
		}
		refs = defaultErrorHandlers
	} else {
		refs = configuredErrorHandlers
	}

	var ehs []pipeline.ErrorHandler
	for _, ref := range refs {
		eh, err := pr.ErrorHandler(ref.Id)
		if err != nil {
			return nil, err
		}
		nhe, err := eh.WithConfig(ref.Config)
		if err != nil {
			return nil, err
		}
		ehs = append(ehs, nhe)
	}

	return &compositeErrorHandler{
		ehs: ehs,
	}, nil
}

func newRule(pr pipeline.Repository, p config.Pipeline, srcId string, rc config.RuleConfig) (*rule, error) {
	an, err := createAuthenticator(pr, rc.Authenticators, p.Authenticators)
	if err != nil {
		return nil, err
	}

	az, err := createAuthorizer(pr, rc.Authorizer, p.Authorizer)
	if err != nil {
		return nil, err
	}

	h, err := createHydrator(pr, rc.Hydrators, p.Hydrators)
	if err != nil {
		return nil, err
	}

	m, err := createMutator(pr, rc.Mutators, p.Mutators)
	if err != nil {
		return nil, err
	}

	eh, err := createErrorHandler(pr, rc.ErrorHandlers, p.ErrorHandlers)
	if err != nil {
		return nil, err
	}

	return &rule{
		id:    rc.Id,
		url:   rc.Url,
		srcId: srcId,
		an:    an,
		az:    az,
		h:     h,
		m:     m,
		eh:    eh,
	}, nil
}

type rule struct {
	id    string
	url   string
	srcId string
	an    pipeline.Authenticator
	az    pipeline.Authorizer
	h     pipeline.Hydrator
	m     pipeline.Mutator
	eh    pipeline.ErrorHandler
}

func (r *rule) Execute(ctx context.Context, ads interfaces.AuthDataSource) (*heimdall.SubjectContext, error) {
	sc := &heimdall.SubjectContext{}

	if err := r.an.Authenticate(ctx, ads, sc); err != nil {
		return nil, r.eh.HandleError(ctx, err)
	}

	if err := r.az.Authorize(ctx, sc); err != nil {
		return nil, r.eh.HandleError(ctx, err)
	}

	if err := r.h.Hydrate(ctx, sc); err != nil {
		return nil, r.eh.HandleError(ctx, err)
	}

	if err := r.m.Mutate(ctx, sc); err != nil {
		return nil, r.eh.HandleError(ctx, err)
	}

	return sc, nil
}

func (r *rule) Matches(requestUrl *url.URL) bool {
	return true
}

func (r *rule) Id() string {
	return r.id
}

type compositeAuthenticator struct {
	ans []pipeline.Authenticator
}

func (ca *compositeAuthenticator) Authenticate(c context.Context, ads interfaces.AuthDataSource, sc *heimdall.SubjectContext) error {
	var err error
	for _, a := range ca.ans {
		err = a.Authenticate(c, ads, sc)
		if err != nil {
			// try next
			continue
		} else {
			return nil
		}
	}
	return err
}

func (ca *compositeAuthenticator) WithConfig(_ json.RawMessage) (pipeline.Authenticator, error) {
	return nil, errors.New("reconfiguration not allowed")
}

type compositeHydrator struct {
	hs []pipeline.Hydrator
}

func (ca *compositeHydrator) Hydrate(c context.Context, sc *heimdall.SubjectContext) error {
	var err error
	for _, h := range ca.hs {
		err = h.Hydrate(c, sc)
		if err != nil {
			// try next
			continue
		} else {
			return nil
		}
	}
	return err
}

func (ca *compositeHydrator) WithConfig(_ json.RawMessage) (pipeline.Hydrator, error) {
	return nil, errors.New("reconfiguration not allowed")
}

type compositeMutator struct {
	ms []pipeline.Mutator
}

func (ca *compositeMutator) Mutate(c context.Context, sc *heimdall.SubjectContext) error {
	var err error
	for _, m := range ca.ms {
		err = m.Mutate(c, sc)
		if err != nil {
			// try next
			continue
		} else {
			return nil
		}
	}
	return err
}

func (ca *compositeMutator) WithConfig(_ json.RawMessage) (pipeline.Mutator, error) {
	return nil, errors.New("reconfiguration not allowed")
}

type compositeErrorHandler struct {
	ehs []pipeline.ErrorHandler
}

func (ceh *compositeErrorHandler) HandleError(ctx context.Context, e error) error {
	var err error
	for _, eh := range ceh.ehs {
		err = eh.HandleError(ctx, e)
		if err != nil {
			// try next
			continue
		} else {
			return nil
		}
	}
	return err
}

func (*compositeErrorHandler) WithConfig(_ json.RawMessage) (pipeline.ErrorHandler, error) {
	return nil, errors.New("reconfiguration not allowed")
}
