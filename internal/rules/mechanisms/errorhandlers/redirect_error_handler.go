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
	"github.com/dadrus/heimdall/internal/rules/mechanisms/errorhandlers/matcher"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerErrorHandlerTypeFactory(
		func(id string, typ string, conf map[string]any) (bool, ErrorHandler, error) {
			if typ != ErrorHandlerRedirect {
				return false, nil, nil
			}

			eh, err := newRedirectErrorHandler(id, conf)

			return true, eh, err
		})
}

type redirectErrorHandler struct {
	id   string
	to   template.Template
	code int
	m    []matcher.ErrorConditionMatcher
}

func newRedirectErrorHandler(id string, rawConfig map[string]any) (*redirectErrorHandler, error) {
	type Config struct {
		To   template.Template               `mapstructure:"to"`
		Code int                             `mapstructure:"code"`
		When []matcher.ErrorConditionMatcher `mapstructure:"when"`
	}

	var conf Config
	if err := decodeConfig(rawConfig, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to unmarshal redirect error handler config").
			CausedBy(err)
	}

	if conf.To == nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration,
				"redirect error handler requires 'to' parameter to be set")
	}

	if len(conf.When) == 0 {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration,
				"no 'when' error handler conditions defined for the redirect error handler")
	}

	return &redirectErrorHandler{
		id:   id,
		to:   conf.To,
		code: x.IfThenElse(conf.Code != 0, conf.Code, http.StatusFound),
		m:    conf.When,
	}, nil
}

func (eh *redirectErrorHandler) Execute(ctx heimdall.Context, err error) (bool, error) {
	logger := zerolog.Ctx(ctx.AppContext())

	for _, ecm := range eh.m {
		if !ecm.Match(ctx, err) {
			return false, nil
		}
	}

	logger.Debug().Str("_id", eh.id).Msg("Handling error using redirect error handler")

	toURL, err := eh.to.Render(ctx, nil)
	if err != nil {
		return true, errorchain.NewWithMessage(heimdall.ErrInternal, "failed to render 'to' url").
			CausedBy(err)
	}

	ctx.SetPipelineError(&heimdall.RedirectError{
		Message:    "redirect",
		Code:       eh.code,
		RedirectTo: toURL,
	})

	return true, nil
}

func (eh *redirectErrorHandler) WithConfig(rawConfig map[string]any) (ErrorHandler, error) {
	if len(rawConfig) == 0 {
		return eh, nil
	}

	type Config struct {
		When []matcher.ErrorConditionMatcher `mapstructure:"when"`
	}

	var conf Config
	if err := decodeConfig(rawConfig, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to unmarshal redirect error handler config").
			CausedBy(err)
	}

	if len(conf.When) == 0 {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration,
				"no error handler conditions defined for the redirect error handler")
	}

	return &redirectErrorHandler{
		id:   eh.id,
		to:   eh.to,
		code: eh.code,
		m:    conf.When,
	}, nil
}

func (eh *redirectErrorHandler) HandlerID() string { return eh.id }
