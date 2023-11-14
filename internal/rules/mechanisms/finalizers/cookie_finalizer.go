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
		func(id string, typ string, conf map[string]any) (bool, Finalizer, error) {
			if typ != FinalizerCookie {
				return false, nil, nil
			}

			finalizer, err := newCookieFinalizer(id, conf)

			return true, finalizer, err
		})
}

type cookieFinalizer struct {
	id      string
	cookies map[string]template.Template
}

func newCookieFinalizer(id string, rawConfig map[string]any) (*cookieFinalizer, error) {
	type Config struct {
		Cookies map[string]template.Template `mapstructure:"cookies" validate:"required,gt=0"`
	}

	var conf Config
	if err := decodeConfig(FinalizerCookie, rawConfig, &conf); err != nil {
		return nil, err
	}

	return &cookieFinalizer{
		id:      id,
		cookies: conf.Cookies,
	}, nil
}

func (u *cookieFinalizer) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Str("_id", u.id).Msg("Finalizing using cookie finalizer")

	if sub == nil {
		return errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to execute cookie finalizer due to 'nil' subject").
			WithErrorContext(u)
	}

	for name, tmpl := range u.cookies {
		value, err := tmpl.Render(map[string]any{
			"Request": ctx.Request(),
			"Subject": sub,
		})
		if err != nil {
			return errorchain.
				NewWithMessagef(heimdall.ErrInternal, "failed to render value for '%s' cookie", name).
				WithErrorContext(u).
				CausedBy(err)
		}

		logger.Debug().Str("_value", value).Msg("Rendered template")

		ctx.AddCookieForUpstream(name, value)
	}

	return nil
}

func (u *cookieFinalizer) WithConfig(config map[string]any) (Finalizer, error) {
	if len(config) == 0 {
		return u, nil
	}

	return newCookieFinalizer(u.id, config)
}

func (u *cookieFinalizer) ID() string { return u.id }

func (u *cookieFinalizer) ContinueOnError() bool { return false }
