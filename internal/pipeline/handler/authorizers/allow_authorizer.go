package authorizers

import (
	"context"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
)

type allowAuthorizer struct{}

func NewAllowAuthorizer() *allowAuthorizer {
	return &allowAuthorizer{}
}

func (*allowAuthorizer) Authorize(context.Context, handler.RequestContext, *heimdall.SubjectContext) error {
	return nil
}

func (a *allowAuthorizer) WithConfig(map[string]any) (handler.Authorizer, error) {
	return a, nil
}
