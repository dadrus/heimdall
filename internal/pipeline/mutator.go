package pipeline

import (
	"context"

	"github.com/dadrus/heimdall/internal/heimdall"
)

type Mutator interface {
	Mutate(context.Context, *heimdall.SubjectContext) error
}
