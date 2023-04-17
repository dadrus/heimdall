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

package unifiers

import (
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerUnifierTypeFactory(
		func(id string, typ string, conf map[string]any) (bool, Unifier, error) {
			if typ != UnifierHeader {
				return false, nil, nil
			}

			unifier, err := newHeaderUnifier(id, conf)

			return true, unifier, err
		})
}

type headerUnifier struct {
	id      string
	headers map[string]template.Template
}

func newHeaderUnifier(id string, rawConfig map[string]any) (*headerUnifier, error) {
	type Config struct {
		Headers map[string]template.Template `mapstructure:"headers"`
	}

	var conf Config
	if err := decodeConfig(rawConfig, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to unmarshal header unifier config").
			CausedBy(err)
	}

	if len(conf.Headers) == 0 {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "no headers definitions provided")
	}

	return &headerUnifier{
		id:      id,
		headers: conf.Headers,
	}, nil
}

func (u *headerUnifier) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Str("_id", u.id).Msg("Unifying using header unifier")

	if sub == nil {
		return errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to execute header unifier due to 'nil' subject").
			WithErrorContext(u)
	}

	for name, tmpl := range u.headers {
		value, err := tmpl.Render(nil, sub, nil)
		if err != nil {
			return errorchain.
				NewWithMessagef(heimdall.ErrInternal, "failed to render value for '%s' cookie", name).
				WithErrorContext(u).
				CausedBy(err)
		}

		ctx.AddHeaderForUpstream(name, value)
	}

	return nil
}

func (u *headerUnifier) WithConfig(config map[string]any) (Unifier, error) {
	if len(config) == 0 {
		return u, nil
	}

	return newHeaderUnifier(u.id, config)
}

func (u *headerUnifier) HandlerID() string { return u.id }

func (u *headerUnifier) ContinueOnError() bool { return false }
