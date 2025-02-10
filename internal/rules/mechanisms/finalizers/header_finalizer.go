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

package finalizers

import (
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap
//
//nolint:gochecknoinits
func init() {
	registerTypeFactory(
		func(app app.Context, id string, typ string, conf map[string]any) (bool, Finalizer, error) {
			if typ != FinalizerHeader {
				return false, nil, nil
			}

			finalizer, err := newHeaderFinalizer(app, id, conf)

			return true, finalizer, err
		})
}

type headerFinalizer struct {
	id      string
	app     app.Context
	headers map[string]template.Template
}

func newHeaderFinalizer(app app.Context, id string, rawConfig map[string]any) (*headerFinalizer, error) {
	logger := app.Logger()
	logger.Info().Str("_id", id).Msg("Creating header finalizer")

	type Config struct {
		Headers map[string]template.Template `mapstructure:"headers" validate:"required,gt=0"`
	}

	var conf Config
	if err := decodeConfig(app.Validator(), rawConfig, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed decoding config for header finalizer '%s'", id).CausedBy(err)
	}

	return &headerFinalizer{
		id:      id,
		app:     app,
		headers: conf.Headers,
	}, nil
}

func (f *headerFinalizer) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Str("_id", f.id).Msg("Finalizing using header finalizer")

	if sub == nil {
		return errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to execute header finalizer due to 'nil' subject").
			WithErrorContext(f)
	}

	for name, tmpl := range f.headers {
		value, err := tmpl.Render(map[string]any{
			"Request": ctx.Request(),
			"Subject": sub,
			"Outputs": ctx.Outputs(),
		})
		if err != nil {
			return errorchain.
				NewWithMessagef(heimdall.ErrInternal, "failed to render value for '%s' header", name).
				WithErrorContext(f).
				CausedBy(err)
		}

		logger.Debug().Str("_value", value).Msg("Rendered template")

		ctx.AddHeaderForUpstream(name, value)
	}

	return nil
}

func (f *headerFinalizer) WithConfig(config map[string]any) (Finalizer, error) {
	if len(config) == 0 {
		return f, nil
	}

	return newHeaderFinalizer(f.app, f.id, config)
}

func (f *headerFinalizer) ID() string { return f.id }

func (f *headerFinalizer) ContinueOnError() bool { return false }
