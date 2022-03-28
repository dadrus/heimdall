package authorizers

import (
	"context"

	"github.com/dadrus/heimdall/internal/errorsx"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
)

type denyAuthorizer struct{}

func NewDenyAuthorizer() *denyAuthorizer {
	return &denyAuthorizer{}
}

func (*denyAuthorizer) Authorize(context.Context, handler.RequestContext, *heimdall.SubjectContext) error {
	return &errorsx.ForbiddenError{
		Message: "not authorized",
	}
}

func (a *denyAuthorizer) WithConfig([]byte) (handler.Authorizer, error) {
	return a, nil
}
