package mutators

import (
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
)

type Mutator interface {
	Mutate(ctx heimdall.Context, sub *subject.Subject) error
	WithConfig(config map[string]any) (Mutator, error)
}
