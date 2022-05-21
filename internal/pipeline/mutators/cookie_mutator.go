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
		func(_ string, typ config.PipelineObjectType, conf map[string]any) (bool, Mutator, error) {
			if typ != config.POTCookie {
				return false, nil, nil
			}

			mut, err := newCookieMutator(conf)

			return true, mut, err
		})
}

type cookieMutator struct {
	cookies map[string]template.Template
}

func newCookieMutator(rawConfig map[string]any) (*cookieMutator, error) {
	type _config struct {
		Cookies map[string]template.Template `mapstructure:"cookies"`
	}

	var conf _config
	if err := decodeConfig(rawConfig, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to unmarshal cookie mutator config").
			CausedBy(err)
	}

	if len(conf.Cookies) == 0 {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "no cookie definitions provided")
	}

	return &cookieMutator{
		cookies: conf.Cookies,
	}, nil
}

func (m *cookieMutator) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Mutating using cookie mutator")

	if sub == nil {
		return errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed to execute cookie mutator due to 'nil' subject")
	}

	for name, tmpl := range m.cookies {
		value, err := tmpl.Render(nil, sub)
		if err != nil {
			return errorchain.NewWithMessagef(heimdall.ErrInternal,
				"failed to render value for '%s' cookie", name).CausedBy(err)
		}

		ctx.AddResponseCookie(name, value)
	}

	return nil
}

func (m *cookieMutator) WithConfig(config map[string]any) (Mutator, error) {
	if len(config) == 0 {
		return m, nil
	}

	return newCookieMutator(config)
}
