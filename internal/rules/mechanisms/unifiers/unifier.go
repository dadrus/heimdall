package unifiers

import (
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
)

type Unifier interface {
	Execute(ctx heimdall.Context, sub *subject.Subject) error
	WithConfig(config map[string]any) (Unifier, error)
}
