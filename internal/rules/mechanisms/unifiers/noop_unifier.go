package unifiers

import (
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerUnifierTypeFactory(
		func(_ string, typ string, conf map[string]any) (bool, Unifier, error) {
			if typ != UnifierNoop {
				return false, nil, nil
			}

			return true, newNoopUnifier(), nil
		})
}

func newNoopUnifier() *noopUnifier { return &noopUnifier{} }

type noopUnifier struct{}

func (m *noopUnifier) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Unifying using noop unifier")

	return nil
}

func (m *noopUnifier) WithConfig(map[string]any) (Unifier, error) { return m, nil }
