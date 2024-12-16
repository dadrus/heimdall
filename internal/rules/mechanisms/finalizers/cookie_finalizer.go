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
			if typ != FinalizerCookie {
				return false, nil, nil
			}

			finalizer, err := newCookieFinalizer(app, id, conf)

			return true, finalizer, err
		})
}

type cookieFinalizer struct {
	id      string
	app     app.Context
	cookies map[string]template.Template
}

func newCookieFinalizer(app app.Context, id string, rawConfig map[string]any) (*cookieFinalizer, error) {
	type Config struct {
		Cookies map[string]template.Template `mapstructure:"cookies" validate:"required,gt=0"`
	}

	var conf Config
	if err := decodeConfig(app.Validator(), FinalizerCookie, rawConfig, &conf); err != nil {
		return nil, err
	}

	return &cookieFinalizer{
		id:      id,
		app:     app,
		cookies: conf.Cookies,
	}, nil
}

func (f *cookieFinalizer) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Str("_id", f.id).Msg("Finalizing using cookie finalizer")

	if sub == nil {
		return errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to execute cookie finalizer due to 'nil' subject").
			WithErrorContext(f)
	}

	for name, tmpl := range f.cookies {
		value, err := tmpl.Render(map[string]any{
			"Request": ctx.Request(),
			"Subject": sub,
			"Outputs": ctx.Outputs(),
		})
		if err != nil {
			return errorchain.
				NewWithMessagef(heimdall.ErrInternal, "failed to render value for '%s' cookie", name).
				WithErrorContext(f).
				CausedBy(err)
		}

		logger.Debug().Str("_value", value).Msg("Rendered template")

		ctx.AddCookieForUpstream(name, value)
	}

	return nil
}

func (f *cookieFinalizer) WithConfig(config map[string]any) (Finalizer, error) {
	if len(config) == 0 {
		return f, nil
	}

	return newCookieFinalizer(f.app, f.id, config)
}

func (f *cookieFinalizer) ID() string { return f.id }

func (f *cookieFinalizer) ContinueOnError() bool { return false }
