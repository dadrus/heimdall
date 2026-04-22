// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
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
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/registry"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
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
		types.KindErrorHandler,
		ErrorHandlerGeneric,
		registry.FactoryFunc(newGenericErrorHandler),
	)
}

type genericErrorHandler struct {
	name    string
	id      string
	app     app.Context
	code    int
	headers []HeaderEntry
	body    template.Template
	values  values.Values
}

func newGenericErrorHandler(app app.Context, name string, rawConfig map[string]any) (types.Mechanism, error) {
	logger := app.Logger()
	logger.Info().
		Str("_type", ErrorHandlerGeneric).
		Str("_name", name).
		Msg("Creating error handler")

	type Config struct {
		Code    int               `mapstructure:"code"    validate:"required,gte=100,lt=600"`
		Headers []HeaderEntry     `mapstructure:"headers"`
		Body    template.Template `mapstructure:"body"`
		Values  values.Values     `mapstructure:"values"`
	}

	var conf Config
	if err := decodeConfig(app.Validator(), rawConfig, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(pipeline.ErrConfiguration,
			"failed decoding config for %s error handler '%s'", ErrorHandlerGeneric, name).
			CausedBy(err)
	}

	return &genericErrorHandler{
		name:    name,
		id:      name,
		app:     app,
		code:    conf.Code,
		headers: conf.Headers,
		body:    conf.Body,
		values:  conf.Values,
	}, nil
}

func (eh *genericErrorHandler) Accept(_ pipeline.Visitor) {}
func (eh *genericErrorHandler) ID() string                { return eh.id }
func (eh *genericErrorHandler) Name() string              { return eh.name }
func (*genericErrorHandler) Type() string                 { return ErrorHandlerGeneric }
func (*genericErrorHandler) Kind() types.Kind             { return types.KindErrorHandler }

func (eh *genericErrorHandler) CreateStep(def types.StepDefinition) (pipeline.Step, error) {
	if len(def.ID) == 0 && len(def.Config) == 0 {
		return eh, nil
	}

	if len(def.Config) == 0 {
		erh := *eh
		erh.id = def.ID

		return &erh, nil
	}

	type Config struct {
		Code    int               `mapstructure:"code"    validate:"omitempty,gte=100,lt=600"`
		Headers []HeaderEntry     `mapstructure:"headers"`
		Body    template.Template `mapstructure:"body"`
		Values  values.Values     `mapstructure:"values"`
	}

	var conf Config
	if err := decodeConfig(eh.app.Validator(), def.Config, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(pipeline.ErrConfiguration,
			"failed decoding config for %s error handler '%s'", ErrorHandlerGeneric, eh.name).
			CausedBy(err)
	}

	return &genericErrorHandler{
		id:      x.IfThenElse(len(def.ID) == 0, eh.id, def.ID),
		name:    eh.name,
		app:     eh.app,
		code:    x.IfThenElse(conf.Code != 0, conf.Code, eh.code),
		headers: x.IfThenElse(len(conf.Headers) != 0, conf.Headers, eh.headers),
		body:    x.IfThenElse(conf.Body != nil, conf.Body, eh.body),
		values:  eh.values.Merge(conf.Values),
	}, nil
}

func (eh *genericErrorHandler) Execute(ctx pipeline.Context, _ pipeline.Subject) error {
	logger := zerolog.Ctx(ctx.Context())
	logger.Debug().
		Str("_type", ErrorHandlerGeneric).
		Str("_name", eh.name).
		Str("_id", eh.id).
		Msg("Executing error handler")

	vals, err := eh.values.Render(map[string]any{
		"Request": ctx.Request(),
	})
	if err != nil {
		return errorchain.NewWithMessage(pipeline.ErrInternal, "failed to render values").
			CausedBy(err)
	}

	headers, err := eh.renderHeaders(ctx, vals)
	if err != nil {
		return err
	}

	body, err := eh.renderBody(ctx, vals)
	if err != nil {
		return err
	}

	ctx.SetError(&pipeline.GenericError{
		Code:    eh.code,
		Headers: headers,
		Body:    body,
		Cause:   ctx.Error(),
	})

	return nil
}

func (eh *genericErrorHandler) renderHeaders(
	ctx pipeline.Context,
	vals map[string]string,
) (map[string][]string, error) {
	var headers map[string][]string

	if len(eh.headers) == 0 {
		return headers, nil
	}

	headers = make(map[string][]string, len(eh.headers))
	for _, he := range eh.headers {
		value, err := he.Value.Render(map[string]any{
			"Request": ctx.Request(),
			"Values":  vals,
		})
		if err != nil {
			return nil, errorchain.NewWithMessage(pipeline.ErrInternal,
				"failed to render header '"+he.Name+"'").
				CausedBy(err)
		}

		headers[he.Name] = append(headers[he.Name], value)
	}

	return headers, nil
}

func (eh *genericErrorHandler) renderBody(ctx pipeline.Context, vals map[string]string) (string, error) {
	if eh.body == nil {
		return "", nil
	}

	body, err := eh.body.Render(map[string]any{
		"Request": ctx.Request(),
		"Values":  vals,
	})
	if err != nil {
		return "", errorchain.NewWithMessage(pipeline.ErrInternal, "failed to render body").
			CausedBy(err)
	}

	return body, err
}
