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
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap
//
//nolint:gochecknoinits
func init() {
	registerTypeFactory(
		func(app app.Context, id string, typ string, conf map[string]any) (bool, ErrorHandler, error) {
			if typ != ErrorHandlerRedirect {
				return false, nil, nil
			}

			eh, err := newRedirectErrorHandler(app, id, conf)

			return true, eh, err
		})
}

type redirectErrorHandler struct {
	id   string
	to   template.Template
	code int
}

func newRedirectErrorHandler(app app.Context, id string, rawConfig map[string]any) (*redirectErrorHandler, error) {
	logger := app.Logger()
	logger.Info().Str("_id", id).Msg("Creating redirect error handler")

	type Config struct {
		To   template.Template `mapstructure:"to"   validate:"required,enforced=istls"`
		Code int               `mapstructure:"code"`
	}

	var conf Config
	if err := decodeConfig(app.Validator(), ErrorHandlerRedirect, rawConfig, &conf); err != nil {
		return nil, err
	}

	if strings.HasPrefix(conf.To.String(), "http://") {
		logger.Warn().Str("_id", id).
			Msg("No TLS configured for the redirect endpoint used in redirect error handler")
	}

	return &redirectErrorHandler{
		id:   id,
		to:   conf.To,
		code: x.IfThenElse(conf.Code != 0, conf.Code, http.StatusFound),
	}, nil
}

func (eh *redirectErrorHandler) ID() string { return eh.id }

func (eh *redirectErrorHandler) Execute(ctx heimdall.RequestContext, _ error) error {
	logger := zerolog.Ctx(ctx.Context())
	logger.Debug().Str("_id", eh.id).Msg("Handling error using redirect error handler")

	toURL, err := eh.to.Render(map[string]any{
		"Request": ctx.Request(),
	})
	if err != nil {
		return errorchain.NewWithMessage(heimdall.ErrInternal, "failed to render 'to' url").
			CausedBy(err)
	}

	ctx.SetPipelineError(&heimdall.RedirectError{
		Message:    "redirect",
		Code:       eh.code,
		RedirectTo: toURL,
	})

	return nil
}

func (eh *redirectErrorHandler) WithConfig(stepID string, conf map[string]any) (ErrorHandler, error) {
	if len(conf) != 0 {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"reconfiguration of a redirect error handler is not supported")
	}

	return eh, nil
}
