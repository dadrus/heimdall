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
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap.
func init() { // nolint: gochecknoinits
	registerTypeFactory(
		func(app app.Context, id string, typ string, conf map[string]any) (bool, Authenticator, error) {
			if typ != AuthenticatorAnonymous {
				return false, nil, nil
			}

			auth, err := newAnonymousAuthenticator(app, id, conf)

			return true, auth, err
		})
}

func newAnonymousAuthenticator(
	app app.Context,
	id string,
	rawConfig map[string]any,
) (*anonymousAuthenticator, error) {
	logger := app.Logger()
	logger.Info().Str("_id", id).Msg("Creating anonymous authenticator")

	var auth anonymousAuthenticator

	if err := decodeConfig(app, rawConfig, &auth); err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed decoding config for anonymous authenticator '%s'", id).CausedBy(err)
	}

	if len(auth.Subject) == 0 {
		auth.Subject = "anonymous"
	}

	auth.id = id
	auth.app = app

	return &auth, nil
}

type anonymousAuthenticator struct {
	id      string
	app     app.Context
	Subject string `mapstructure:"subject"`
}

func (a *anonymousAuthenticator) Execute(ctx heimdall.RequestContext) (*subject.Subject, error) {
	logger := zerolog.Ctx(ctx.Context())
	logger.Debug().Str("_id", a.id).Msg("Authenticating using anonymous authenticator")

	return &subject.Subject{ID: a.Subject, Attributes: make(map[string]any)}, nil
}

func (a *anonymousAuthenticator) WithConfig(stepID string, config map[string]any) (Authenticator, error) {
	// this authenticator allows subject to be redefined on the rule level
	if len(config) == 0 {
		return a, nil
	}

	return newAnonymousAuthenticator(a.app, a.id, config)
}

func (a *anonymousAuthenticator) ID() string {
	return a.id
}

func (a *anonymousAuthenticator) IsInsecure() bool { return true }
