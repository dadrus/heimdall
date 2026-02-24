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
	"net/http"
	"strings"

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
		types.KindErrorHandler,
		ErrorHandlerRedirect,
		registry.FactoryFunc(newRedirectErrorHandler),
	)
}

type redirectErrorHandler struct {
	name string
	id   string
	to   template.Template
	code int
}

func newRedirectErrorHandler(app app.Context, name string, rawConfig map[string]any) (types.Mechanism, error) {
	logger := app.Logger()
	logger.Info().
		Str("_type", ErrorHandlerRedirect).
		Str("_name", name).
		Msg("Creating error handler")

	type Config struct {
		To   template.Template `mapstructure:"to"   validate:"required,enforced=istls"`
		Code int               `mapstructure:"code"`
	}

	var conf Config
	if err := decodeConfig(app.Validator(), rawConfig, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(pipeline.ErrConfiguration,
			"failed decoding config for %s error handler '%s'", ErrorHandlerRedirect, name).
			CausedBy(err)
	}

	if strings.HasPrefix(conf.To.String(), "http://") {
		logger.Warn().
			Str("_type", ErrorHandlerRedirect).
			Str("_name", name).
			Msg("No TLS configured for the endpoint used in error handler")
	}

	return &redirectErrorHandler{
		name: name,
		id:   name,
		to:   conf.To,
		code: x.IfThenElse(conf.Code != 0, conf.Code, http.StatusFound),
	}, nil
}

func (eh *redirectErrorHandler) Accept(_ pipeline.Visitor) {}
func (eh *redirectErrorHandler) Kind() types.Kind          { return types.KindErrorHandler }
func (eh *redirectErrorHandler) Name() string              { return eh.name }
func (eh *redirectErrorHandler) ID() string                { return eh.id }
func (eh *redirectErrorHandler) Type() string              { return eh.name }

func (eh *redirectErrorHandler) Execute(ctx pipeline.Context, _ pipeline.Subject) error {
	logger := zerolog.Ctx(ctx.Context())
	logger.Debug().
		Str("_type", ErrorHandlerRedirect).
		Str("_name", eh.name).
		Str("_id", eh.id).
		Msg("Executing error handler")

	toURL, err := eh.to.Render(map[string]any{
		"Request": ctx.Request(),
	})
	if err != nil {
		return errorchain.NewWithMessage(pipeline.ErrInternal, "failed to render 'to' url").
			CausedBy(err)
	}

	ctx.SetError(&pipeline.RedirectError{
		Message:    "redirect",
		Code:       eh.code,
		RedirectTo: toURL,
	})

	return nil
}

func (eh *redirectErrorHandler) CreateStep(def types.StepDefinition) (pipeline.Step, error) {
	if len(def.ID) == 0 && len(def.Config) == 0 {
		return eh, nil
	}

	if len(def.Config) == 0 {
		erh := *eh
		erh.id = def.ID

		return &erh, nil
	}

	return nil, errorchain.NewWithMessage(pipeline.ErrConfiguration,
		"reconfiguration of a redirect error handler is not supported")
}
