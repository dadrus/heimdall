package mutators

import (
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerMutatorTypeFactory(
		func(typ config.PipelineObjectType, conf map[string]any) (bool, Mutator, error) {
			if typ != config.POTHeader {
				return false, nil, nil
			}

			mut, err := newHeaderMutator(conf)

			return true, mut, err
		})
}

type headerMutator struct {
	headers map[string]Template
}

func newHeaderMutator(rawConfig map[string]any) (*headerMutator, error) {
	type _config struct {
		Headers map[string]Template `mapstructure:"headers"`
	}

	var conf _config
	if err := decodeConfig(rawConfig, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to unmarshal header mutator config").
			CausedBy(err)
	}

	return &headerMutator{
		headers: conf.Headers,
	}, nil
}

func (m *headerMutator) Mutate(ctx heimdall.Context, sub *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Mutating using header mutator")

	for name, tmpl := range m.headers {
		value, err := tmpl.Render(sub)
		if err != nil {
			return err
		}

		ctx.AddResponseHeader(name, value)
	}

	return nil
}

func (m *headerMutator) WithConfig(config map[string]any) (Mutator, error) {
	if len(config) == 0 {
		return m, nil
	}

	return newHeaderMutator(config)
}
