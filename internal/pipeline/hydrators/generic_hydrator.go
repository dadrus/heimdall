package hydrators

import (
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerHydratorTypeFactory(
		func(typ config.PipelineObjectType, conf map[any]any) (bool, Hydrator, error) {
			if typ != config.POTGeneric {
				return false, nil, nil
			}

			eh, err := newGenericHydrator(conf)

			return true, eh, err
		})
}

type genericHydrator struct{}

func newGenericHydrator(rawConfig map[any]any) (genericHydrator, error) {
	return genericHydrator{}, nil
}

func (genericHydrator) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Hydrating using generic hydrator")

	return nil
}

func (genericHydrator) WithConfig(config map[any]any) (Hydrator, error) {
	return nil, nil
}
