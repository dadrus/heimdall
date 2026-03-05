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

package authorizers

import (
	"github.com/google/cel-go/cel"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/cellib"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/registry"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/types"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/values"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap
//
//nolint:gochecknoinits
func init() {
	registry.Register(
		types.KindAuthorizer,
		AuthorizerCEL,
		registry.FactoryFunc(newCELAuthorizer),
	)
}

type celAuthorizer struct {
	name        string
	id          string
	app         app.Context
	celEnv      *cel.Env
	expressions compiledExpressions
	v           values.Values
}

func newCELAuthorizer(app app.Context, name string, rawConfig map[string]any) (types.Mechanism, error) {
	logger := app.Logger()
	logger.Info().
		Str("_type", AuthorizerCEL).
		Str("_name", name).
		Msg("Creating authorizer")

	type Config struct {
		Expressions []Expression  `mapstructure:"expressions" validate:"required,gt=0,dive"`
		Values      values.Values `mapstructure:"values"`
	}

	var conf Config
	if err := decodeConfig(app, rawConfig, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(pipeline.ErrConfiguration,
			"failed decoding config for cel authorizer '%s'", name).CausedBy(err)
	}

	env, err := cel.NewEnv(cellib.Library())
	if err != nil {
		return nil, errorchain.NewWithMessage(pipeline.ErrInternal,
			"failed creating CEL environment").CausedBy(err)
	}

	expressions, err := compileExpressions(conf.Expressions, env)
	if err != nil {
		return nil, err
	}

	return &celAuthorizer{
		name:        name,
		id:          name,
		app:         app,
		celEnv:      env,
		expressions: expressions,
		v:           conf.Values,
	}, nil
}

func (a *celAuthorizer) Accept(_ pipeline.Visitor) {}

func (a *celAuthorizer) Execute(ctx pipeline.Context, sub pipeline.Subject) error {
	logger := zerolog.Ctx(ctx.Context())
	logger.Debug().
		Str("_type", AuthorizerCEL).
		Str("_name", a.name).
		Str("_id", a.id).
		Msg("Executing authorizer")

	vals, err := a.v.Render(map[string]any{
		"Request": ctx.Request(),
		"Subject": sub,
		"Outputs": ctx.Outputs(),
	})
	if err != nil {
		return errorchain.NewWithMessage(pipeline.ErrInternal,
			"failed to render values").
			WithErrorContext(a).
			CausedBy(err)
	}

	return a.expressions.eval(map[string]any{
		"Request": ctx.Request(),
		"Subject": cellib.WrapSubject(sub),
		"Values":  vals,
		"Outputs": ctx.Outputs(),
	}, a)
}

func (a *celAuthorizer) CreateStep(def types.StepDefinition) (pipeline.Step, error) {
	if len(def.ID) == 0 && len(def.Config) == 0 {
		return a, nil
	}

	if len(def.Config) == 0 {
		auth := *a
		auth.id = def.ID

		return &auth, nil
	}

	type Config struct {
		Expressions []Expression  `mapstructure:"expressions"`
		Values      values.Values `mapstructure:"values"`
	}

	var conf Config
	if err := decodeConfig(a.app, def.Config, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(pipeline.ErrConfiguration,
			"failed decoding config for cel authorizer '%s'", a.name).CausedBy(err)
	}

	expressions, err := compileExpressions(conf.Expressions, a.celEnv)
	if err != nil {
		return nil, err
	}

	return &celAuthorizer{
		name:        a.name,
		id:          x.IfThenElse(len(def.ID) == 0, a.id, def.ID),
		app:         a.app,
		celEnv:      a.celEnv,
		expressions: x.IfThenElse(len(expressions) != 0, expressions, a.expressions),
		v:           a.v.Merge(conf.Values),
	}, nil
}

func (a *celAuthorizer) Kind() types.Kind { return types.KindAuthorizer }
func (a *celAuthorizer) Name() string     { return a.name }
func (a *celAuthorizer) ID() string       { return a.id }
func (a *celAuthorizer) Type() string     { return a.name }
