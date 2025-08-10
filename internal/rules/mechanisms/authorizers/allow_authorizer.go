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

package authorizers

import (
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
)

// by intention. Used only during application bootstrap
//
//nolint:gochecknoinits
func init() {
	registerTypeFactory(
		func(app app.Context, name string, typ string, _ map[string]any) (bool, Authorizer, error) {
			if typ != AuthorizerAllow {
				return false, nil, nil
			}

			return true, newAllowAuthorizer(app, name), nil
		})
}

type allowAuthorizer struct {
	name string
	id   string
}

func newAllowAuthorizer(app app.Context, name string) *allowAuthorizer {
	logger := app.Logger()
	logger.Info().
		Str("_type", AuthorizerAllow).
		Str("_name", name).
		Msg("Creating authorizer")

	return &allowAuthorizer{
		name: name,
		id:   name,
	}
}

func (a *allowAuthorizer) Execute(ctx heimdall.RequestContext, _ *subject.Subject) error {
	logger := zerolog.Ctx(ctx.Context())
	logger.Debug().
		Str("_type", AuthorizerAllow).
		Str("_name", a.name).
		Str("_id", a.id).
		Msg("Executing authorizer")

	return nil
}

func (a *allowAuthorizer) WithConfig(stepID string, rawConfig map[string]any) (Authorizer, error) {
	if len(stepID) == 0 && len(rawConfig) == 0 {
		return a, nil
	}

	if len(rawConfig) != 0 {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "allow authorizer cannot be reconfigured").
			WithErrorContext(a)
	}

	auth := *a
	auth.id = stepID

	return &auth, nil
}

func (a *allowAuthorizer) Name() string { return a.name }

func (a *allowAuthorizer) ID() string { return a.id }

func (a *allowAuthorizer) ContinueOnError() bool { return false }
