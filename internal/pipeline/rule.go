package pipeline

import (
	"context"

	"github.com/dadrus/heimdall/internal/heimdall"
)

type Rule struct {
	Authenticator Authenticator
	Authorizer    Authorizer
	Hydrator      Hydrator
	Mutator       Mutator
	ErrorHandler  ErrorHandler
}

func (r *Rule) Execute(ctx context.Context, ads AuthDataSource) (*heimdall.SubjectContext, error) {
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
