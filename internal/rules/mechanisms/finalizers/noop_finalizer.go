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

package finalizers

import (
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/identity"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/registry"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/types"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap
//
//nolint:gochecknoinits
func init() {
	registry.Register(
		types.KindFinalizer,
		FinalizerNoop,
		registry.FactoryFunc(newNoopFinalizer),
	)
}

func newNoopFinalizer(app app.Context, name string, _ map[string]any) (types.Mechanism, error) {
	logger := app.Logger()
	logger.Info().
		Str("_type", FinalizerNoop).
		Str("_name", name).
		Msg("Creating finalizer")

	return &noopFinalizer{
		name: name,
		id:   name,
	}, nil
}

type noopFinalizer struct {
	name string
	id   string
}

func (f *noopFinalizer) Accept(_ heimdall.Visitor) {}

func (f *noopFinalizer) Execute(ctx heimdall.Context, _ identity.Subject) error {
	logger := zerolog.Ctx(ctx.Context())
	logger.Debug().
		Str("_type", FinalizerNoop).
		Str("_name", f.name).
		Str("_id", f.id).
		Msg("Executing finalizer")

	return nil
}

func (f *noopFinalizer) CreateStep(def types.StepDefinition) (heimdall.Step, error) {
	if len(def.ID) == 0 && len(def.Config) == 0 {
		return f, nil
	}

	if len(def.Config) != 0 {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "noop finalizer cannot be reconfigured").
			WithErrorContext(f)
	}

	fin := *f
	fin.id = def.ID

	return &fin, nil
}

func (f *noopFinalizer) Kind() types.Kind { return types.KindFinalizer }

func (f *noopFinalizer) Name() string { return f.name }

func (f *noopFinalizer) ID() string { return f.id }
