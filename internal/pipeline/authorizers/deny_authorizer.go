package authorizers

import (
	"context"

	"github.com/dadrus/heimdall/internal/errorsx"
	"github.com/dadrus/heimdall/internal/heimdall"
)

type denyAuthorizer struct{}

func NewDenyAuthorizer() denyAuthorizer {
	return denyAuthorizer{}
}

func (denyAuthorizer) Authorize(context.Context, *heimdall.SubjectContext) error {
	return &errorsx.ForbiddenError{
		Message: "not authorized",
	}
}
