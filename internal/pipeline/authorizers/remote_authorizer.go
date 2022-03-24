package authorizers

import (
	"context"

	"github.com/dadrus/heimdall/internal/heimdall"
)

type RemoteAuthorizer struct{}

func (*RemoteAuthorizer) Authorize(context.Context, *heimdall.SubjectContext) error {
	return nil
}
