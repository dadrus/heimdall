package hydrators

import (
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
	"github.com/dadrus/heimdall/internal/pipeline/handler/subject"
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	handler.RegisterHydratorTypeFactory(
		func(typ config.PipelineObjectType, conf map[string]any) (bool, handler.Hydrator, error) {
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
	return nil
}

func (defaultHydrator) WithConfig(config map[string]any) (handler.Hydrator, error) {
	return nil, nil
}
