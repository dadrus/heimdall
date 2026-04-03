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

package authenticators

import (
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/registry"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/types"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap
//
//nolint:gochecknoinits
func init() {
	registry.Register(
		types.KindAuthenticator,
		AuthenticatorAnonymous,
		registry.FactoryFunc(newAnonymousAuthenticator),
	)
}

func newAnonymousAuthenticator(app app.Context, name string, rawConfig map[string]any) (types.Mechanism, error) {
	logger := app.Logger()
	logger.Info().
		Str("_type", AuthenticatorAnonymous).
		Str("_name", name).
		Msg("Creating authenticator")

	type Config struct {
		Principal string `mapstructure:"principal"`
	}

	var conf Config

	if err := decodeConfig(app, rawConfig, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(pipeline.ErrConfiguration,
			"failed decoding config for %s authenticator '%s'", AuthenticatorAnonymous, name).CausedBy(err)
	}

	if len(conf.Principal) == 0 {
		conf.Principal = "anonymous"
	}

	return &anonymousAuthenticator{
		name:          name,
		id:            name,
		principalName: DefaultPrincipalName,
		principal:     &pipeline.Principal{ID: conf.Principal, Attributes: make(map[string]any)},
		app:           app,
	}, nil
}

type anonymousAuthenticator struct {
	name          string
	id            string
	principalName string
	app           app.Context
	principal     *pipeline.Principal
}

func (a *anonymousAuthenticator) Accept(visitor pipeline.Visitor) {
	visitor.VisitInsecure(a)
	visitor.VisitPrincipalNamer(a)
}

func (a *anonymousAuthenticator) Execute(ctx pipeline.Context, sub pipeline.Subject) error {
	logger := zerolog.Ctx(ctx.Context())
	logger.Debug().
		Str("_type", AuthenticatorAnonymous).
		Str("_name", a.name).
		Str("_id", a.id).
		Msg("Executing authenticator")

	sub[a.principalName] = a.principal

	return nil
}

func (a *anonymousAuthenticator) CreateStep(def types.StepDefinition) (pipeline.Step, error) {
	if def.IsEmpty() {
		return a, nil
	}

	if len(def.Config) == 0 {
		auth := *a
		auth.id = x.IfThenElse(len(def.ID) == 0, a.id, def.ID)
		auth.principalName = x.IfThenElse(len(def.Principal) == 0, a.principalName, def.Principal)

		return &auth, nil
	}

	type Config struct {
		Principal string `mapstructure:"principal" validate:"required"`
	}

	var conf Config

	if err := decodeConfig(a.app, def.Config, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(pipeline.ErrConfiguration,
			"failed decoding config for %s authenticator '%s'", AuthenticatorAnonymous, a.name).CausedBy(err)
	}

	return &anonymousAuthenticator{
		name:          a.name,
		id:            x.IfThenElse(len(def.ID) == 0, a.id, def.ID),
		principalName: x.IfThenElse(len(def.Principal) == 0, a.principalName, def.Principal),
		principal:     &pipeline.Principal{ID: conf.Principal, Attributes: a.principal.Attributes},
		app:           a.app,
	}, nil
}

func (a *anonymousAuthenticator) Kind() types.Kind      { return types.KindAuthenticator }
func (a *anonymousAuthenticator) Name() string          { return a.name }
func (a *anonymousAuthenticator) ID() string            { return a.id }
func (a *anonymousAuthenticator) Type() string          { return a.name }
func (a *anonymousAuthenticator) IsInsecure() bool      { return true }
func (a *anonymousAuthenticator) PrincipalName() string { return a.principalName }
