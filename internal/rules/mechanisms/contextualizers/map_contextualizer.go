package contextualizers

import (
	"fmt"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/values"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap
//
//nolint:gochecknoinits
func init() {
	registerTypeFactory(
		func(app app.Context, id string, typ string, conf map[string]any) (bool, Contextualizer, error) {
			if typ != ContextualizerMap {
				return false, nil, nil
			}

			eh, err := newMapContextualizer(app, id, conf)

			return true, eh, err
		})
}

func newMapContextualizer(app app.Context, id string, rawConfig map[string]any) (*mapContextualizer, error) {
	logger := app.Logger()
	logger.Info().Str("_id", id).Msg("Creating map contextualizer")

	type Config struct {
		Items  map[string]template.Template `mapstructure:"items"`
		Values values.Values                `mapstructure:"values"`
	}

	var conf Config
	if err := decodeConfig(app, rawConfig, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed decoding config for map contextualizer '%s'", id).CausedBy(err)
	}

	return &mapContextualizer{
		id:     id,
		app:    app,
		items:  conf.Items,
		values: conf.Values,
	}, nil
}

type mapContextualizer struct {
	id     string
	app    app.Context
	items  map[string]template.Template
	values values.Values
}

func (m *mapContextualizer) ContinueOnError() bool {
	return false
}

func (m *mapContextualizer) Execute(ctx heimdall.RequestContext, sub *subject.Subject) error {
	if sub == nil {
		return errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed to execute map contextualizer due to 'nil' subject").
			WithErrorContext(m)
	}

	resp, err := m.renderTemplates(ctx, sub)
	if err != nil {
		return errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed to render templates for the map contextualizer").WithErrorContext(m).CausedBy(err)
	}

	if resp != nil {
		ctx.Outputs()[m.id] = resp
	}

	return nil
}

func (m *mapContextualizer) ID() string {
	return m.id
}

func (m *mapContextualizer) WithConfig(rawConfig map[string]any) (Contextualizer, error) {
	if len(rawConfig) == 0 {
		return m, nil
	}

	type Config struct {
		Values values.Values `mapstructure:"values"`
	}

	var conf Config
	if err := decodeConfig(m.app, rawConfig, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed decoding config for map contextualizer '%s'", m.id).CausedBy(err)
	}

	return &mapContextualizer{
		id:     m.id,
		app:    m.app,
		items:  m.items,
		values: m.values.Merge(conf.Values),
	}, nil
}

func (m *mapContextualizer) renderTemplates(
	ctx heimdall.RequestContext,
	sub *subject.Subject,
) (map[string]string, error) {
	var (
		vals     map[string]string
		rendered string
		err      error
	)

	if vals, err = m.values.Render(map[string]any{
		"Request": ctx.Request(),
		"Subject": sub,
		"Outputs": ctx.Outputs(),
	}); err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed to render values for the map contextualizer").
			WithErrorContext(m).
			CausedBy(err)
	}

	resp := make(map[string]string, len(m.items))

	for key, tmpl := range m.items {
		if rendered, err = tmpl.Render(map[string]any{
			"Request": ctx.Request(),
			"Subject": sub,
			"Values":  vals,
			"Outputs": ctx.Outputs(),
		}); err != nil {
			return nil, errorchain.NewWithMessage(heimdall.ErrInternal,
				fmt.Sprintf("failed to render item %s for the map contextualizer", key)).
				WithErrorContext(m).
				CausedBy(err)
		}

		resp[key] = rendered
	}

	return resp, nil
}
