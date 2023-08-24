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
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
)

// by intention. Used only during application bootstrap
//
//nolint:gochecknoinits
func init() {
	registerAuthenticatorTypeFactory(
		func(id string, typ string, conf map[string]any) (bool, Authenticator, error) {
			if typ != AuthenticatorNoop {
				return false, nil, nil
			}

			return true, newNoopAuthenticator(id), nil
		})
}

type noopAuthenticator struct {
	id string
}

func newNoopAuthenticator(id string) *noopAuthenticator {
	return &noopAuthenticator{id: id}
}

func (a *noopAuthenticator) Execute(ctx heimdall.Context) (*subject.Subject, error) {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Str("_id", a.id).Msg("Authenticating using noop authenticator")

	return &subject.Subject{}, nil
}

func (a *noopAuthenticator) WithConfig(_ map[string]any) (Authenticator, error) {
	// nothing can be reconfigured
	return a, nil
}

func (a *noopAuthenticator) IsFallbackOnErrorAllowed() bool {
	// not allowed, as no error can happen when this authenticator is executed
	return false
}

func (a *noopAuthenticator) ID() string { return a.id }
