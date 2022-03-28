package handler

import (
	"context"
	"encoding/json"

	"github.com/dadrus/heimdall/internal/heimdall"
)

type Hydrator interface {
	Hydrate(context.Context, *heimdall.SubjectContext) error
	WithConfig(config json.RawMessage) (Hydrator, error)
}
