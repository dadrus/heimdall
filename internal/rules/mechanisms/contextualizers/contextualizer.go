package contextualizers

import (
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
)

type Contextualizer interface {
	Execute(heimdall.Context, *subject.Subject) error
	WithConfig(config map[string]any) (Contextualizer, error)
}
