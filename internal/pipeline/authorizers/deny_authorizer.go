package authorizers

import (
	"context"

	"github.com/dadrus/heimdall/internal/errorsx"
	"github.com/dadrus/heimdall/internal/heimdall"
)

type DenyAuthorizer struct{}

func (*DenyAuthorizer) Authorize(context.Context, *heimdall.SubjectContext) error {
	return &errorsx.ForbiddenError{
		Message: "not authorized",
	}
}
