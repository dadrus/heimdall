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
	"github.com/dadrus/heimdall/internal/rules/mechanisms/values"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/google/cel-go/cel"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/cellib"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap
//
//nolint:gochecknoinits
func init() {
	registerTypeFactory(
		func(app app.Context, id string, typ string, conf map[string]any) (bool, Authorizer, error) {
			if typ != AuthorizerCEL {
				return false, nil, nil
			}

			auth, err := newCELAuthorizer(app, id, conf)

			return true, auth, err
		})
}

type celAuthorizer struct {
	id          string
	app         app.Context
	celEnv      *cel.Env
	expressions compiledExpressions
	v           values.Values
}

func newCELAuthorizer(app app.Context, id string, rawConfig map[string]any) (*celAuthorizer, error) {
	logger := app.Logger()
	logger.Info().Str("_id", id).Msg("Creating cel authorizer")

	type Config struct {
		Expressions []Expression  `mapstructure:"expressions" validate:"required,gt=0,dive"`
		Values      values.Values `mapstructure:"values"`
	}

	var conf Config
	if err := decodeConfig(app, rawConfig, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed decoding config for cel authorizer '%s'", id).CausedBy(err)
	}

	env, err := cel.NewEnv(cellib.Library())
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed creating CEL environment").CausedBy(err)
	}

	expressions, err := compileExpressions(conf.Expressions, env)
	if err != nil {
		return nil, err
	}

	return &celAuthorizer{
		id:          id,
		app:         app,
		celEnv:      env,
		expressions: expressions,
		v:           conf.Values,
	}, nil
}

func (a *celAuthorizer) Execute(ctx heimdall.RequestContext, sub *subject.Subject) error {
	logger := zerolog.Ctx(ctx.Context())
	logger.Debug().Str("_id", a.id).Msg("Authorizing using CEL authorizer")

	vals, err := a.v.Render(map[string]any{
		"Request": ctx.Request(),
		"Subject": sub,
		"Outputs": ctx.Outputs(),
	})
	if err != nil {
		return errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed to render values").
			WithErrorContext(a).
			CausedBy(err)
	}

	return a.expressions.eval(map[string]any{
		"Request": ctx.Request(),
		"Subject": sub,
		"Values":  vals,
		"Outputs": ctx.Outputs(),
	}, a)
}

func (a *celAuthorizer) WithConfig(rawConfig map[string]any) (Authorizer, error) {
	if len(rawConfig) == 0 {
		return a, nil
	}

	type Config struct {
		Expressions []Expression  `mapstructure:"expressions"`
		Values      values.Values `mapstructure:"values"`
	}

	var conf Config
	if err := decodeConfig(a.app, rawConfig, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed decoding config for cel authorizer '%s'", a.id).CausedBy(err)
	}

	expressions, err := compileExpressions(conf.Expressions, a.celEnv)
	if err != nil {
		return nil, err
	}

	return &celAuthorizer{
		id:          a.id,
		app:         a.app,
		celEnv:      a.celEnv,
		expressions: x.IfThenElse(len(expressions) != 0, expressions, a.expressions),
		v:           a.v.Merge(conf.Values),
	}, nil
}

func (a *celAuthorizer) ID() string { return a.id }

func (a *celAuthorizer) ContinueOnError() bool { return false }
