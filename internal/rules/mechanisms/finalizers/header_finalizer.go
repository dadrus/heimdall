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
	"strings"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap
//
//nolint:gochecknoinits
func init() {
	registerTypeFactory(
		func(app app.Context, name string, typ string, conf map[string]any) (bool, Finalizer, error) {
			if typ != FinalizerHeader {
				return false, nil, nil
			}

			finalizer, err := newHeaderFinalizer(app, name, conf)

			return true, finalizer, err
		})
}

type headerFinalizer struct {
	name    string
	id      string
	app     app.Context
	headers map[string]template.Template
}

func newHeaderFinalizer(app app.Context, name string, rawConfig map[string]any) (*headerFinalizer, error) {
	logger := app.Logger()
	logger.Info().
		Str("_type", FinalizerHeader).
		Str("_name", name).
		Msg("Creating finalizer")

	type Config struct {
		Headers map[string]template.Template `mapstructure:"headers" validate:"required,gt=0"`
	}

	var conf Config
	if err := decodeConfig(app.Validator(), rawConfig, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed decoding config for header finalizer '%s'", name).CausedBy(err)
	}

	return &headerFinalizer{
		name:    name,
		id:      name,
		app:     app,
		headers: conf.Headers,
	}, nil
}

func (f *headerFinalizer) Execute(ctx heimdall.RequestContext, sub *subject.Subject) error {
	logger := zerolog.Ctx(ctx.Context())
	logger.Debug().
		Str("_type", FinalizerHeader).
		Str("_name", f.name).
		Str("_id", f.id).
		Msg("Executing finalizer")

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

		// Split the rendered value into multiple values if newline-separated
		values := strings.Split(value, "\n")
		for _, v := range values {
			if len(v) != 0 {
				ctx.AddHeaderForUpstream(name, v)
			}
		}
	}

	return nil
}

func (f *headerFinalizer) WithConfig(stepID string, rawConfig map[string]any) (Finalizer, error) {
	if len(stepID) == 0 && len(rawConfig) == 0 {
		return f, nil
	}

	if len(rawConfig) == 0 {
		fin := *f
		fin.id = stepID

		return &fin, nil
	}

	type Config struct {
		Headers map[string]template.Template `mapstructure:"headers" validate:"required,gt=0"`
	}

	var conf Config
	if err := decodeConfig(f.app.Validator(), rawConfig, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed decoding config for header finalizer '%s'", f.name).CausedBy(err)
	}

	return &headerFinalizer{
		name:    f.name,
		id:      x.IfThenElse(len(stepID) == 0, f.id, stepID),
		app:     f.app,
		headers: conf.Headers,
	}, nil
}

func (f *headerFinalizer) Name() string { return f.name }

func (f *headerFinalizer) ID() string { return f.id }

func (f *headerFinalizer) ContinueOnError() bool { return false }
