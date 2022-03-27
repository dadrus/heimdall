package pipeline

import (
	"context"
	"encoding/json"

	"github.com/dadrus/heimdall/internal/heimdall"
)

type Mutator interface {
	Mutate(context.Context, *heimdall.SubjectContext) error
	WithConfig(config json.RawMessage) (Mutator, error)
}
