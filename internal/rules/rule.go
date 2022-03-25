package rules

import (
	"context"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/pipeline/interfaces"
)

type Rule struct {
	Authenticator pipeline.Authenticator
	Authorizer    pipeline.Authorizer
	Hydrator      pipeline.Hydrator
	Mutator       pipeline.Mutator
	ErrorHandler  pipeline.ErrorHandler
}

func (r *Rule) Execute(ctx context.Context, ads interfaces.AuthDataSource) (*heimdall.SubjectContext, error) {
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
