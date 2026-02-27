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
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/registry"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/types"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap
//
//nolint:gochecknoinits
func init() {
	registry.Register(
		types.KindAuthorizer,
		AuthorizerAllow,
		registry.FactoryFunc(newAllowAuthorizer),
	)
}

type allowAuthorizer struct {
	name string
	id   string
}

func newAllowAuthorizer(app app.Context, name string, _ map[string]any) (types.Mechanism, error) {
	logger := app.Logger()
	logger.Info().
		Str("_type", AuthorizerAllow).
		Str("_name", name).
		Msg("Creating authorizer")

	return &allowAuthorizer{
		name: name,
		id:   name,
	}, nil
}

func (a *allowAuthorizer) Accept(_ pipeline.Visitor) {}

func (a *allowAuthorizer) Execute(ctx pipeline.Context, _ pipeline.Subject) error {
	logger := zerolog.Ctx(ctx.Context())
	logger.Debug().
		Str("_type", AuthorizerAllow).
		Str("_name", a.name).
		Str("_id", a.id).
		Msg("Executing authorizer")

	return nil
}

func (a *allowAuthorizer) CreateStep(def types.StepDefinition) (pipeline.Step, error) {
	if len(def.ID) == 0 && len(def.Config) == 0 {
		return a, nil
	}

	if len(def.Config) != 0 {
		return nil, errorchain.
			NewWithMessage(pipeline.ErrConfiguration, "allow authorizer cannot be reconfigured").
			WithErrorContext(a)
	}

	auth := *a
	auth.id = def.ID

	return &auth, nil
}

func (a *allowAuthorizer) Kind() types.Kind { return types.KindAuthorizer }
func (a *allowAuthorizer) Name() string     { return a.name }
func (a *allowAuthorizer) ID() string       { return a.id }
func (a *allowAuthorizer) Type() string     { return a.name }
