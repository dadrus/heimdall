package mutators

import (
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerMutatorTypeFactory(
		func(_ string, typ string, conf map[string]any) (bool, Mutator, error) {
			if typ != MutatorNoop {
				return false, nil, nil
			}

			return true, newNoopMutator(), nil
		})
}

func newNoopMutator() *noopMutator {
	return &noopMutator{}
}

type noopMutator struct{}

func (m *noopMutator) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Mutating using noop mutator")

	return nil
}

func (m *noopMutator) WithConfig(map[string]any) (Mutator, error) {
	return m, nil
}
