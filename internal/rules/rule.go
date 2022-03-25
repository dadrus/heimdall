package rules

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/pipeline/interfaces"
)

type Rule interface {
	Id() string
	Execute(ctx context.Context, ads interfaces.AuthDataSource) (*heimdall.SubjectContext, error)
	Matches(requestUrl *url.URL, method string) bool
}

func newRule(definition json.RawMessage) (*rule, error) {
	return nil, nil
}

type rule struct {
	id            string
	srcId         string
	Authenticator pipeline.Authenticator
	Authorizer    pipeline.Authorizer
	Hydrator      pipeline.Hydrator
	Mutator       pipeline.Mutator
	ErrorHandler  pipeline.ErrorHandler
}

func (r *rule) Execute(ctx context.Context, ads interfaces.AuthDataSource) (*heimdall.SubjectContext, error) {
	sc := &heimdall.SubjectContext{}

	if err := r.Authenticator.Authenticate(ctx, ads, sc); err != nil {
		return nil, r.ErrorHandler.HandleError(ctx, err)
	}

	if err := r.Authorizer.Authorize(ctx, sc); err != nil {
		return nil, r.ErrorHandler.HandleError(ctx, err)
	}

	if err := r.Hydrator.Hydrate(ctx, sc); err != nil {
		return nil, r.ErrorHandler.HandleError(ctx, err)
	}

	if err := r.Mutator.Mutate(ctx, sc); err != nil {
		return nil, r.ErrorHandler.HandleError(ctx, err)
	}

	return sc, nil
}

func (r *rule) Matches(requestUrl *url.URL, method string) bool {
	return true
}

func (r *rule) Id() string {
	return r.id
}
