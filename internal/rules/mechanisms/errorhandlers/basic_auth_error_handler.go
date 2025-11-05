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

package errorhandlers

import (
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/identity"
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
		types.KindErrorHandler,
		ErrorHandlerWWWAuthenticate,
		registry.FactoryFunc(newWWWAuthenticateErrorHandler),
	)
}

type wwwAuthenticateErrorHandler struct {
	name  string
	id    string
	app   app.Context
	realm string
}

func newWWWAuthenticateErrorHandler(app app.Context, name string, rawConfig map[string]any) (types.Mechanism, error) {
	logger := app.Logger()
	logger.Info().
		Str("_type", ErrorHandlerWWWAuthenticate).
		Str("_name", name).
		Msg("Creating error handler")

	type Config struct {
		Realm string `mapstructure:"realm"`
	}

	var conf Config
	if err := decodeConfig(app.Validator(), rawConfig, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed decoding config for %s error handler '%s'", ErrorHandlerWWWAuthenticate, name).CausedBy(err)
	}

	return &wwwAuthenticateErrorHandler{
		name:  name,
		id:    name,
		app:   app,
		realm: x.IfThenElse(len(conf.Realm) != 0, conf.Realm, "Please authenticate"),
	}, nil
}

func (eh *wwwAuthenticateErrorHandler) Kind() types.Kind { return types.KindErrorHandler }

func (eh *wwwAuthenticateErrorHandler) Name() string { return eh.name }

func (eh *wwwAuthenticateErrorHandler) ID() string { return eh.id }

func (eh *wwwAuthenticateErrorHandler) IsInsecure() bool { return false }

func (eh *wwwAuthenticateErrorHandler) Execute(ctx heimdall.Context, _ identity.Subject) error {
	logger := zerolog.Ctx(ctx.Context())
	logger.Debug().
		Str("_type", ErrorHandlerWWWAuthenticate).
		Str("_name", eh.name).
		Str("_id", eh.id).
		Msg("Executing error handler")

	ctx.AddHeaderForUpstream("WWW-Authenticate", "Basic realm="+eh.realm)
	ctx.SetError(heimdall.ErrAuthentication)

	return nil
}

func (eh *wwwAuthenticateErrorHandler) CreateStep(def types.StepDefinition) (heimdall.Step, error) {
	if len(def.ID) == 0 && len(def.Config) == 0 {
		return eh, nil
	}

	if len(def.Config) == 0 {
		erh := *eh
		erh.id = def.ID

		return &erh, nil
	}

	type Config struct {
		Realm string `mapstructure:"realm" validate:"required"`
	}

	var conf Config

	err := decodeConfig(eh.app.Validator(), def.Config, &conf)
	if err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed decoding config for %s error handler '%s'", ErrorHandlerWWWAuthenticate, eh.name).
			CausedBy(err)
	}

	return &wwwAuthenticateErrorHandler{
		name:  eh.name,
		id:    x.IfThenElse(len(def.ID) == 0, eh.id, def.ID),
		app:   eh.app,
		realm: conf.Realm,
	}, nil
}
