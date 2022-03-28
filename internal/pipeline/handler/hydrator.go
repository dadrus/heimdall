package handler

import (
	"context"

	"github.com/dadrus/heimdall/internal/heimdall"
)

type Hydrator interface {
	Hydrate(context.Context, *heimdall.SubjectContext) error
	WithConfig(config []byte) (Hydrator, error)
}
