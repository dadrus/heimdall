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

	"github.com/rs/zerolog"

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
		func(id string, typ string, conf map[string]any) (bool, ErrorHandler, error) {
			if typ != ErrorHandlerRedirect {
				return false, nil, nil
			}

			eh, err := newRedirectErrorHandler(id, conf)

			return true, eh, err
		})
}

type redirectErrorHandler struct {
	*baseErrorHandler

	to   template.Template
	code int
}

func newRedirectErrorHandler(id string, rawConfig map[string]any) (*redirectErrorHandler, error) {
	type Config struct {
		Condition string            `mapstructure:"if"   validate:"required"`
		To        template.Template `mapstructure:"to"   validate:"required"`
		Code      int               `mapstructure:"code"`
	}

	var conf Config
	if err := decodeConfig(ErrorHandlerRedirect, rawConfig, &conf); err != nil {
		return nil, err
	}

	base, err := newBaseErrorHandler(id, conf.Condition)
	if err != nil {
		return nil, err
	}

	return &redirectErrorHandler{
		baseErrorHandler: base,
		to:               conf.To,
		code:             x.IfThenElse(conf.Code != 0, conf.Code, http.StatusFound),
	}, nil
}

func (eh *redirectErrorHandler) Execute(ctx heimdall.Context, _ error) error {
	logger := zerolog.Ctx(ctx.AppContext())
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

func (eh *redirectErrorHandler) WithConfig(rawConfig map[string]any) (ErrorHandler, error) {
	if len(rawConfig) == 0 {
		return eh, nil
	}

	type Config struct {
		Condition string `mapstructure:"if" validate:"required"`
	}

	var conf Config
	if err := decodeConfig(ErrorHandlerRedirect, rawConfig, &conf); err != nil {
		return nil, err
	}

	base, err := newBaseErrorHandler(eh.id, conf.Condition)
	if err != nil {
		return nil, err
	}

	return &redirectErrorHandler{
		baseErrorHandler: base,
		to:               eh.to,
		code:             eh.code,
	}, nil
}
