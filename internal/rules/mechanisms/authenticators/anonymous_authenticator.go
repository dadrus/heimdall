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

// by intention. Used only during application bootstrap.
func init() { // nolint: gochecknoinits
	registerTypeFactory(
		func(ctx CreationContext, id string, typ string, conf map[string]any) (bool, Authenticator, error) {
			if typ != AuthenticatorAnonymous {
				return false, nil, nil
			}

			auth, err := newAnonymousAuthenticator(id, conf)

			return true, auth, err
		})
}

func newAnonymousAuthenticator(id string, rawConfig map[string]any) (*anonymousAuthenticator, error) {
	var auth anonymousAuthenticator

	if err := decodeConfig(AuthenticatorAnonymous, rawConfig, &auth); err != nil {
		return nil, err
	}

	if len(auth.Subject) == 0 {
		auth.Subject = "anonymous"
	}

	auth.id = id

	return &auth, nil
}

type anonymousAuthenticator struct {
	id      string
	Subject string `mapstructure:"subject"`
}

func (a *anonymousAuthenticator) Execute(ctx heimdall.Context) (*subject.Subject, error) {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Str("_id", a.id).Msg("Authenticating using anonymous authenticator")

	return &subject.Subject{ID: a.Subject, Attributes: make(map[string]any)}, nil
}

func (a *anonymousAuthenticator) WithConfig(config map[string]any) (Authenticator, error) {
	// this authenticator allows subject to be redefined on the rule level
	if len(config) == 0 {
		return a, nil
	}

	return newAnonymousAuthenticator(a.id, config)
}

func (a *anonymousAuthenticator) IsFallbackOnErrorAllowed() bool {
	// not allowed, as no error can happen when this authenticator is executed
	return false
}

func (a *anonymousAuthenticator) ID() string {
	return a.id
}
