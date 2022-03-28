package handler

import (
	"context"

	"github.com/dadrus/heimdall/internal/heimdall"
)

type Mutator interface {
	Mutate(context.Context, *heimdall.SubjectContext) error
	WithConfig(config []byte) (Mutator, error)
}
