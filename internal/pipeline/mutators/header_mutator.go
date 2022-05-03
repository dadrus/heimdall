package mutators

import (
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/pipeline/template"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerMutatorTypeFactory(
		func(_ string, typ config.PipelineObjectType, conf map[any]any) (bool, Mutator, error) {
			if typ != config.POTHeader {
				return false, nil, nil
			}

			mut, err := newHeaderMutator(conf)

			return true, mut, err
		})
}

type headerMutator struct {
	headers map[string]template.Template
}

func newHeaderMutator(rawConfig map[any]any) (*headerMutator, error) {
	type _config struct {
		Headers map[string]template.Template `mapstructure:"headers"`
	}

	var conf _config
	if err := decodeConfig(rawConfig, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to unmarshal header mutator config").
			CausedBy(err)
	}

	if len(conf.Headers) == 0 {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "no headers definitions provided")
	}

	return &headerMutator{
		headers: conf.Headers,
	}, nil
}

func (m *headerMutator) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Mutating using header mutator")

	if sub == nil {
		return errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed to execute header mutator due to 'nil' subject")
	}

	for name, tmpl := range m.headers {
		value, err := tmpl.Render(nil, sub)
		if err != nil {
			return errorchain.NewWithMessagef(heimdall.ErrInternal,
				"failed to render value for '%s' cookie", name).CausedBy(err)
		}

		ctx.AddResponseHeader(name, value)
	}

	return nil
}

func (m *headerMutator) WithConfig(config map[any]any) (Mutator, error) {
	if len(config) == 0 {
		return m, nil
	}

	return newHeaderMutator(config)
}
