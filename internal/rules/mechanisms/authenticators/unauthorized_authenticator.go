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

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/subject"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap
//
//nolint:gochecknoinits
func init() {
	registerTypeFactory(
		func(id string, typ string, _ map[string]any) (bool, Authenticator, error) {
			if typ != AuthenticatorUnauthorized {
				return false, nil, nil
			}

			return true, newUnauthorizedAuthenticator(id), nil
		})
}

type unauthorizedAuthenticator struct {
	id string
}

func newUnauthorizedAuthenticator(id string) *unauthorizedAuthenticator {
	return &unauthorizedAuthenticator{id: id}
}

func (a *unauthorizedAuthenticator) Execute(ctx heimdall.Context, _ subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Str("_id", a.id).Msg("Authenticating using unauthorized authenticator")

	return errorchain.
		NewWithMessage(heimdall.ErrAuthentication, "denied by authenticator").
		WithErrorContext(a)
}

func (a *unauthorizedAuthenticator) WithConfig(_ map[string]any) (Authenticator, error) {
	// nothing can be reconfigured
	return a, nil
}

func (a *unauthorizedAuthenticator) ContinueOnError() bool {
	// not allowed, as this authenticator fails always
	return false
}

func (a *unauthorizedAuthenticator) ID() string {
	return a.id
}
