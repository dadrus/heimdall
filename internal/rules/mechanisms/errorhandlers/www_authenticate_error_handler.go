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

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x"
)

// by intention. Used only during application bootstrap
//
//nolint:gochecknoinits
func init() {
	registerTypeFactory(
		func(_ CreationContext, id string, typ string, conf map[string]any) (bool, ErrorHandler, error) {
			if typ != ErrorHandlerWWWAuthenticate {
				return false, nil, nil
			}

			eh, err := newWWWAuthenticateErrorHandler(id, conf)

			return true, eh, err
		})
}

type wwwAuthenticateErrorHandler struct {
	id    string
	realm string
}

func newWWWAuthenticateErrorHandler(id string, rawConfig map[string]any) (*wwwAuthenticateErrorHandler, error) {
	type Config struct {
		Realm string `mapstructure:"realm"`
	}

	var conf Config
	if err := decodeConfig(ErrorHandlerWWWAuthenticate, rawConfig, &conf); err != nil {
		return nil, err
	}

	return &wwwAuthenticateErrorHandler{
		id:    id,
		realm: x.IfThenElse(len(conf.Realm) != 0, conf.Realm, "Please authenticate"),
	}, nil
}

func (eh *wwwAuthenticateErrorHandler) ID() string { return eh.id }

func (eh *wwwAuthenticateErrorHandler) Execute(ctx heimdall.Context, _ error) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Str("_id", eh.id).Msg("Handling error using www-authenticate error handler")

	ctx.AddHeaderForUpstream("WWW-Authenticate", "Basic realm="+eh.realm)
	ctx.SetPipelineError(heimdall.ErrAuthentication)

	return nil
}

func (eh *wwwAuthenticateErrorHandler) WithConfig(rawConfig map[string]any) (ErrorHandler, error) {
	if len(rawConfig) == 0 {
		return eh, nil
	}

	type Config struct {
		Realm string `mapstructure:"realm"`
	}

	var (
		conf Config
		err  error
	)

	if err = decodeConfig(ErrorHandlerWWWAuthenticate, rawConfig, &conf); err != nil {
		return nil, err
	}

	return &wwwAuthenticateErrorHandler{
		id:    eh.id,
		realm: conf.Realm,
	}, nil
}
