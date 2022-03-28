package rules

import (
	"context"
	"net/url"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
)

type Rule interface {
	Id() string
	Execute(ctx context.Context, ads handler.AuthDataSource) (*heimdall.SubjectContext, error)
	MatchesUrl(requestUrl *url.URL) bool
	MatchesMethod(method string) bool
}

func newRule(hf pipeline.HandlerFactory, srcId string, rc config.RuleConfig) (*rule, error) {
	an, err := hf.CreateAuthenticator(rc.Authenticators)
	if err != nil {
		return nil, err
	}

	az, err := hf.CreateAuthorizer(rc.Authorizer)
	if err != nil {
		return nil, err
	}

	h, err := hf.CreateHydrator(rc.Hydrators)
	if err != nil {
		return nil, err
	}

	m, err := hf.CreateMutator(rc.Mutators)
	if err != nil {
		return nil, err
	}

	eh, err := hf.CreateErrorHandler(rc.ErrorHandlers)
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
	an    handler.Authenticator
	az    handler.Authorizer
	h     handler.Hydrator
	m     handler.Mutator
	eh    handler.ErrorHandler
}

func (r *rule) Execute(ctx context.Context, ads handler.AuthDataSource) (*heimdall.SubjectContext, error) {
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

func (r *rule) MatchesUrl(requestUrl *url.URL) bool {
	return true
}

func (r *rule) MatchesMethod(method string) bool {
	return true
}

func (r *rule) Id() string {
	return r.id
}
