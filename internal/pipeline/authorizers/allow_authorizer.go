package authorizers

import (
	"context"

	"github.com/dadrus/heimdall/internal/heimdall"
)

type AllowAuthorizer struct{}

func (*AllowAuthorizer) Authorize(context.Context, *heimdall.SubjectContext) error {
	return nil
}
