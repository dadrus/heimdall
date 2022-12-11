package mutators

import (
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerMutatorTypeFactory(
		func(id string, typ string, conf map[string]any) (bool, Mutator, error) {
			if typ != MutatorHeader {
				return false, nil, nil
			}

			mut, err := newHeaderMutator(id, conf)

			return true, mut, err
		})
}

type headerMutator struct {
	id      string
	headers map[string]template.Template
}

func newHeaderMutator(id string, rawConfig map[string]any) (*headerMutator, error) {
	type Config struct {
		Headers map[string]template.Template `mapstructure:"headers"`
	}

	var conf Config
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
		id:      id,
		headers: conf.Headers,
	}, nil
}

func (m *headerMutator) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Mutating using header mutator")

	if sub == nil {
		return errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to execute header mutator due to 'nil' subject").
			WithErrorContext(m)
	}

	for name, tmpl := range m.headers {
		value, err := tmpl.Render(nil, sub)
		if err != nil {
			return errorchain.
				NewWithMessagef(heimdall.ErrInternal, "failed to render value for '%s' cookie", name).
				WithErrorContext(m).
				CausedBy(err)
		}

		ctx.AddHeaderForUpstream(name, value)
	}

	return nil
}

func (m *headerMutator) WithConfig(config map[string]any) (Mutator, error) {
	if len(config) == 0 {
		return m, nil
	}

	return newHeaderMutator(m.id, config)
}

func (m *headerMutator) HandlerID() string {
	return m.id
}
