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

package authenticators

import (
	"github.com/dadrus/heimdall/internal/x"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap.
func init() { // nolint: gochecknoinits
	registerTypeFactory(
		func(app app.Context, name string, typ string, conf map[string]any) (bool, Authenticator, error) {
			if typ != AuthenticatorAnonymous {
				return false, nil, nil
			}

			auth, err := newAnonymousAuthenticator(app, name, conf)

			return true, auth, err
		})
}

func newAnonymousAuthenticator(
	app app.Context,
	name string,
	rawConfig map[string]any,
) (*anonymousAuthenticator, error) {
	logger := app.Logger()
	logger.Info().
		Str("_type", AuthenticatorAnonymous).
		Str("_name", name).
		Msg("Creating authenticator")

	type Config struct {
		Subject string `mapstructure:"subject"`
	}

	var conf Config

	if err := decodeConfig(app, rawConfig, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed decoding config for anonymous authenticator '%s'", name).CausedBy(err)
	}

	if len(conf.Subject) == 0 {
		conf.Subject = "anonymous"
	}

	return &anonymousAuthenticator{
		name:    name,
		id:      name,
		subject: &subject.Subject{ID: conf.Subject, Attributes: make(map[string]any)},
		app:     app,
	}, nil
}

type anonymousAuthenticator struct {
	name    string
	id      string
	app     app.Context
	subject *subject.Subject
}

func (a *anonymousAuthenticator) Execute(ctx heimdall.RequestContext) (*subject.Subject, error) {
	logger := zerolog.Ctx(ctx.Context())
	logger.Debug().
		Str("_type", AuthenticatorAnonymous).
		Str("_name", a.name).
		Str("_id", a.id).
		Msg("Executing authenticator")

	return a.subject, nil
}

func (a *anonymousAuthenticator) WithConfig(stepID string, rawConfig map[string]any) (Authenticator, error) {
	if len(stepID) == 0 && len(rawConfig) == 0 {
		return a, nil
	}

	if len(rawConfig) == 0 {
		auth := *a
		auth.id = stepID

		return &auth, nil
	}

	type Config struct {
		Subject string `mapstructure:"subject" validate:"required"`
	}

	var conf Config

	if err := decodeConfig(a.app, rawConfig, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed decoding config for anonymous authenticator '%s'", a.name).CausedBy(err)
	}

	return &anonymousAuthenticator{
		name:    a.name,
		id:      x.IfThenElse(len(stepID) == 0, a.id, stepID),
		subject: &subject.Subject{ID: conf.Subject, Attributes: a.subject.Attributes},
		app:     a.app,
	}, nil
}

func (a *anonymousAuthenticator) Name() string { return a.name }

func (a *anonymousAuthenticator) ID() string { return a.id }

func (a *anonymousAuthenticator) IsInsecure() bool { return true }
