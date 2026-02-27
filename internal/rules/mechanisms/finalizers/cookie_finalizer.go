// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package finalizers

import (
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/registry"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/types"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap
//
//nolint:gochecknoinits
func init() {
	registry.Register(
		types.KindFinalizer,
		FinalizerCookie,
		registry.FactoryFunc(newCookieFinalizer),
	)
}

type cookieFinalizer struct {
	name    string
	id      string
	app     app.Context
	cookies map[string]template.Template
}

func newCookieFinalizer(app app.Context, name string, rawConfig map[string]any) (types.Mechanism, error) {
	logger := app.Logger()
	logger.Info().
		Str("_type", FinalizerCookie).
		Str("_name", name).
		Msg("Creating finalizer")

	type Config struct {
		Cookies map[string]template.Template `mapstructure:"cookies" validate:"required,gt=0"`
	}

	var conf Config
	if err := decodeConfig(app.Validator(), rawConfig, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(pipeline.ErrConfiguration,
			"failed decoding config for cookie finalizer '%s'", name).CausedBy(err)
	}

	return &cookieFinalizer{
		name:    name,
		id:      name,
		app:     app,
		cookies: conf.Cookies,
	}, nil
}

func (f *cookieFinalizer) Accept(_ pipeline.Visitor) {}

func (f *cookieFinalizer) Execute(ctx pipeline.Context, sub pipeline.Subject) error {
	logger := zerolog.Ctx(ctx.Context())
	logger.Debug().
		Str("_type", FinalizerCookie).
		Str("_name", f.name).
		Str("_id", f.id).
		Msg("Executing finalizer")

	for name, tmpl := range f.cookies {
		value, err := tmpl.Render(map[string]any{
			"Request": ctx.Request(),
			"Subject": sub,
			"Outputs": ctx.Outputs(),
		})
		if err != nil {
			return errorchain.
				NewWithMessagef(pipeline.ErrInternal, "failed to render value for '%s' cookie", name).
				WithErrorContext(f).
				CausedBy(err)
		}

		logger.Debug().Str("_value", value).Msg("Rendered template")

		ctx.AddCookieForUpstream(name, value)
	}

	return nil
}

func (f *cookieFinalizer) CreateStep(def types.StepDefinition) (pipeline.Step, error) {
	if len(def.ID) == 0 && len(def.Config) == 0 {
		return f, nil
	}

	if len(def.Config) == 0 {
		fin := *f
		fin.id = def.ID

		return &fin, nil
	}

	type Config struct {
		Cookies map[string]template.Template `mapstructure:"cookies" validate:"required,gt=0"`
	}

	var conf Config
	if err := decodeConfig(f.app.Validator(), def.Config, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(pipeline.ErrConfiguration,
			"failed decoding config for cookie finalizer '%s'", f.name).CausedBy(err)
	}

	return &cookieFinalizer{
		name:    f.name,
		id:      x.IfThenElse(len(def.ID) == 0, f.id, def.ID),
		app:     f.app,
		cookies: conf.Cookies,
	}, nil
}

func (f *cookieFinalizer) Kind() types.Kind { return types.KindFinalizer }
func (f *cookieFinalizer) Name() string     { return f.name }
func (f *cookieFinalizer) ID() string       { return f.id }
func (f *cookieFinalizer) Type() string     { return f.name }
