package pipeline

import (
	"context"

	"github.com/dadrus/heimdall/internal/heimdall"
)

type Authorizer interface {
	Authorize(context.Context, *heimdall.SubjectContext) error
}
