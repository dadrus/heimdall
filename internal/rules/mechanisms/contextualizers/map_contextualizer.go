package contextualizers

import (
	"fmt"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/values"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap
//
//nolint:gochecknoinits
func init() {
	registerTypeFactory(
		func(app app.Context, name string, typ string, conf map[string]any) (bool, Contextualizer, error) {
			if typ != ContextualizerMap {
				return false, nil, nil
			}

			eh, err := newMapContextualizer(app, name, conf)

			return true, eh, err
		})
}

func newMapContextualizer(app app.Context, name string, rawConfig map[string]any) (*mapContextualizer, error) {
	logger := app.Logger()
	logger.Info().
		Str("_type", ContextualizerMap).
		Str("_name", name).
		Msg("Creating contextualizer")

	type Config struct {
		Items  map[string]template.Template `mapstructure:"items"`
		Values values.Values                `mapstructure:"values"`
	}

	var conf Config
	if err := decodeConfig(app, rawConfig, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed decoding config for map contextualizer '%s'", name).CausedBy(err)
	}

	return &mapContextualizer{
		name:   name,
		id:     name,
		app:    app,
		items:  conf.Items,
		values: conf.Values,
	}, nil
}

type mapContextualizer struct {
	name   string
	id     string
	app    app.Context
	items  map[string]template.Template
	values values.Values
}

func (c *mapContextualizer) ContinueOnError() bool {
	return false
}

func (c *mapContextualizer) Execute(ctx heimdall.RequestContext, sub *subject.Subject) error {
	logger := zerolog.Ctx(ctx.Context())
	logger.Debug().
		Str("_type", ContextualizerMap).
		Str("_name", c.name).
		Str("_id", c.id).
		Msg("Executing contextualizer")

	resp, err := c.renderTemplates(ctx, sub)
	if err != nil {
		return errorchain.NewWithMessage(heimdall.ErrInternal, "failed to render templates for the map contextualizer").
			WithErrorContext(c).
			CausedBy(err)
	}

	if resp != nil {
		ctx.Outputs()[c.id] = resp
	}

	return nil
}

func (c *mapContextualizer) Name() string { return c.name }

func (c *mapContextualizer) ID() string { return c.id }

func (c *mapContextualizer) WithConfig(stepID string, rawConfig map[string]any) (Contextualizer, error) {
	if len(stepID) == 0 && len(rawConfig) == 0 {
		return c, nil
	}

	if len(rawConfig) == 0 {
		cont := *c
		cont.id = stepID

		return &cont, nil
	}

	type Config struct {
		Values values.Values `mapstructure:"values"`
	}

	var conf Config
	if err := decodeConfig(c.app, rawConfig, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed decoding config for map contextualizer '%s'", c.name).CausedBy(err)
	}

	return &mapContextualizer{
		name:   c.name,
		id:     x.IfThenElse(len(stepID) == 0, c.id, stepID),
		app:    c.app,
		items:  c.items,
		values: c.values.Merge(conf.Values),
	}, nil
}

func (c *mapContextualizer) renderTemplates(
	ctx heimdall.RequestContext,
	sub *subject.Subject,
) (map[string]string, error) {
	var (
		vals     map[string]string
		rendered string
		err      error
	)

	if vals, err = c.values.Render(map[string]any{
		"Request": ctx.Request(),
		"Subject": sub,
		"Outputs": ctx.Outputs(),
	}); err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed to render values for the map contextualizer").
			WithErrorContext(c).
			CausedBy(err)
	}

	resp := make(map[string]string, len(c.items))

	for key, tmpl := range c.items {
		if rendered, err = tmpl.Render(map[string]any{
			"Request": ctx.Request(),
			"Subject": sub,
			"Values":  vals,
			"Outputs": ctx.Outputs(),
		}); err != nil {
			return nil, errorchain.NewWithMessage(heimdall.ErrInternal,
				fmt.Sprintf("failed to render item %s for the map contextualizer", key)).
				WithErrorContext(c).
				CausedBy(err)
		}

		resp[key] = rendered
	}

	return resp, nil
}
