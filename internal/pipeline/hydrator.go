package pipeline

import (
	"context"

	"github.com/dadrus/heimdall/internal/heimdall"
)

type Hydrator interface {
	Hydrate(context.Context, *heimdall.SubjectContext) error
}
