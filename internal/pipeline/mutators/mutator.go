package mutators

import (
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/keystore"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
)

type Mutator interface {
	Mutate(heimdall.Context, *subject.Subject, *keystore.Entry) error
	WithConfig(config map[string]any) (Mutator, error)
}
