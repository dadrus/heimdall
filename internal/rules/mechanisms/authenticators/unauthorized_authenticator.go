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
	"github.com/dadrus/heimdall/internal/rules/mechanisms/identity"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/registry"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/types"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap
//
//nolint:gochecknoinits
func init() {
	registry.Register(
		types.KindAuthenticator,
		AuthenticatorUnauthorized,
		registry.FactoryFunc(newUnauthorizedAuthenticator),
	)
}

type unauthorizedAuthenticator struct {
	name string
	id   string
}

func newUnauthorizedAuthenticator(app app.Context, name string, _ map[string]any) (types.Mechanism, error) {
	logger := app.Logger()
	logger.Info().
		Str("_type", AuthenticatorUnauthorized).
		Str("_name", name).
		Msg("Creating authenticator")

	return &unauthorizedAuthenticator{
		name: name,
		id:   name,
	}, nil
}

func (a *unauthorizedAuthenticator) Accept(visitor heimdall.Visitor) {
	visitor.VisitPrincipalNamer(a)
}

func (a *unauthorizedAuthenticator) Execute(ctx heimdall.Context, _ identity.Subject) error {
	logger := zerolog.Ctx(ctx.Context())
	logger.Debug().
		Str("_type", AuthenticatorUnauthorized).
		Str("_name", a.name).
		Str("_id", a.id).
		Msg("Executing authenticator")

	return errorchain.
		NewWithMessage(heimdall.ErrAuthentication, "denied by authenticator").
		WithErrorContext(a)
}

func (a *unauthorizedAuthenticator) CreateStep(def types.StepDefinition) (heimdall.Step, error) {
	// nothing can be reconfigured
	if len(def.Config) != 0 {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "unauthorized authenticator cannot be reconfigured").
			WithErrorContext(a)
	}

	if def.IsEmpty() {
		return a, nil
	}

	auth := *a
	auth.id = x.IfThenElse(len(def.ID) == 0, a.id, def.ID)

	return &auth, nil
}

func (a *unauthorizedAuthenticator) Kind() types.Kind { return types.KindAuthenticator }

func (a *unauthorizedAuthenticator) Name() string { return a.name }

func (a *unauthorizedAuthenticator) ID() string {
	return a.id
}

func (a *unauthorizedAuthenticator) PrincipalName() string { return DefaultPrincipalName }
