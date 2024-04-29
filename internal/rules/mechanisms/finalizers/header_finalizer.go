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
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
	"github.com/dadrus/heimdall/internal/subject"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap
//
//nolint:gochecknoinits
func init() {
	registerTypeFactory(
		func(id string, typ string, conf map[string]any) (bool, Finalizer, error) {
			if typ != FinalizerHeader {
				return false, nil, nil
			}

			finalizer, err := newHeaderFinalizer(id, conf)

			return true, finalizer, err
		})
}

type headerFinalizer struct {
	id      string
	headers map[string]template.Template
}

func newHeaderFinalizer(id string, rawConfig map[string]any) (*headerFinalizer, error) {
	type Config struct {
		Headers map[string]template.Template `mapstructure:"headers" validate:"required,gt=0"`
	}

	var conf Config
	if err := decodeConfig(FinalizerHeader, rawConfig, &conf); err != nil {
		return nil, err
	}

	return &headerFinalizer{
		id:      id,
		headers: conf.Headers,
	}, nil
}

func (u *headerFinalizer) Execute(ctx heimdall.Context, sub subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Str("_id", u.id).Msg("Finalizing using header finalizer")

	for name, tmpl := range u.headers {
		value, err := tmpl.Render(map[string]any{
			"Request": ctx.Request(),
			"Subject": sub["Subject"],
		})
		if err != nil {
			return errorchain.
				NewWithMessagef(heimdall.ErrInternal, "failed to render value for '%s' header", name).
				WithErrorContext(u).
				CausedBy(err)
		}

		logger.Debug().Str("_value", value).Msg("Rendered template")

		ctx.AddHeaderForUpstream(name, value)
	}

	return nil
}

func (u *headerFinalizer) WithConfig(config map[string]any) (Finalizer, error) {
	if len(config) == 0 {
		return u, nil
	}

	return newHeaderFinalizer(u.id, config)
}

func (u *headerFinalizer) ID() string { return u.id }

func (u *headerFinalizer) ContinueOnError() bool { return false }
