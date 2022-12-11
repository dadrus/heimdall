package mutators

import (
	"github.com/dadrus/heimdall/internal/rules/pipeline/subject"
	"github.com/dadrus/heimdall/internal/rules/pipeline/template"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerMutatorTypeFactory(
		func(id string, typ string, conf map[string]any) (bool, Mutator, error) {
			if typ != MutatorCookie {
				return false, nil, nil
			}

			mut, err := newCookieMutator(id, conf)

			return true, mut, err
		})
}

type cookieMutator struct {
	id      string
	cookies map[string]template.Template
}

func newCookieMutator(id string, rawConfig map[string]any) (*cookieMutator, error) {
	type Config struct {
		Cookies map[string]template.Template `mapstructure:"cookies"`
	}

	var conf Config
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
		id:      id,
		cookies: conf.Cookies,
	}, nil
}

func (m *cookieMutator) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Mutating using cookie mutator")

	if sub == nil {
		return errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to execute cookie mutator due to 'nil' subject").
			WithErrorContext(m)
	}

	for name, tmpl := range m.cookies {
		value, err := tmpl.Render(nil, sub)
		if err != nil {
			return errorchain.
				NewWithMessagef(heimdall.ErrInternal, "failed to render value for '%s' cookie", name).
				WithErrorContext(m).
				CausedBy(err)
		}

		ctx.AddCookieForUpstream(name, value)
	}

	return nil
}

func (m *cookieMutator) WithConfig(config map[string]any) (Mutator, error) {
	if len(config) == 0 {
		return m, nil
	}

	return newCookieMutator(m.id, config)
}

func (m *cookieMutator) HandlerID() string {
	return m.id
}
