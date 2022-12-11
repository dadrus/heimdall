package hydrators

import (
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
)

type Hydrator interface {
	Execute(heimdall.Context, *subject.Subject) error
	WithConfig(config map[string]any) (Hydrator, error)
}
