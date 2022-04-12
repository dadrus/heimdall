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
		func(typ config.PipelineObjectType, conf map[string]any) (bool, Hydrator, error) {
			if typ != config.POTDefault {
				return false, nil, nil
			}

			eh, err := newDefaultHydrator(conf)

			return true, eh, err
		})
}

type defaultHydrator struct{}

func newDefaultHydrator(rawConfig map[string]any) (defaultHydrator, error) {
	return defaultHydrator{}, nil
}

func (defaultHydrator) Hydrate(ctx heimdall.Context, sub *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Hydrating using default hydrator")

	return nil
}

func (defaultHydrator) WithConfig(config map[string]any) (Hydrator, error) {
	return nil, nil
}
