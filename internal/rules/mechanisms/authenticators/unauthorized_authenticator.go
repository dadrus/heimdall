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

// by intention. Used only during application bootstrap
//
//nolint:gochecknoinits
func init() {
	registerTypeFactory(
		func(app app.Context, name string, typ string, _ map[string]any) (bool, Authenticator, error) {
			if typ != AuthenticatorUnauthorized {
				return false, nil, nil
			}

			return true, newUnauthorizedAuthenticator(app, name), nil
		})
}

type unauthorizedAuthenticator struct {
	name string
	id   string
}

func newUnauthorizedAuthenticator(app app.Context, name string) *unauthorizedAuthenticator {
	logger := app.Logger()
	logger.Info().
		Str("_type", AuthenticatorUnauthorized).
		Str("_name", name).
		Msg("Creating authenticator")

	return &unauthorizedAuthenticator{
		name: name,
		id:   name,
	}
}

func (a *unauthorizedAuthenticator) Execute(ctx heimdall.RequestContext) (*subject.Subject, error) {
	logger := zerolog.Ctx(ctx.Context())
	logger.Debug().
		Str("_type", AuthenticatorUnauthorized).
		Str("_name", a.name).
		Str("_id", a.id).
		Msg("Executing authenticator")

	return nil, errorchain.
		NewWithMessage(heimdall.ErrAuthentication, "denied by authenticator").
		WithErrorContext(a)
}

func (a *unauthorizedAuthenticator) WithConfig(stepID string, rawConfig map[string]any) (Authenticator, error) {
	// nothing can be reconfigured
	if len(stepID) == 0 && len(rawConfig) == 0 {
		return a, nil
	}

	if len(rawConfig) != 0 {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "unauthorized authenticator cannot be reconfigured").
			WithErrorContext(a)
	}

	auth := *a
	auth.id = stepID

	return &auth, nil
}

func (a *unauthorizedAuthenticator) Name() string { return a.name }

func (a *unauthorizedAuthenticator) ID() string {
	return a.id
}

func (a *unauthorizedAuthenticator) IsInsecure() bool { return false }
