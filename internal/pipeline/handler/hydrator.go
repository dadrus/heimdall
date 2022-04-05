package handler

import (
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler/subject"
)

type Hydrator interface {
	Hydrate(heimdall.Context, *subject.Subject) error
	WithConfig(config map[string]any) (Hydrator, error)
}
