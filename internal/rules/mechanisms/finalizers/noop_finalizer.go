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
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap
//
//nolint:gochecknoinits
func init() {
	registerTypeFactory(
		func(app app.Context, name string, typ string, _ map[string]any) (bool, Finalizer, error) {
			if typ != FinalizerNoop {
				return false, nil, nil
			}

			return true, newNoopFinalizer(app, name), nil
		})
}

func newNoopFinalizer(app app.Context, name string) *noopFinalizer {
	logger := app.Logger()
	logger.Info().
		Str("_type", FinalizerNoop).
		Str("_name", name).
		Msg("Creating finalizer")

	return &noopFinalizer{
		name: name,
		id:   name,
	}
}

type noopFinalizer struct {
	name string
	id   string
}

func (f *noopFinalizer) Execute(ctx heimdall.RequestContext, _ *subject.Subject) error {
	logger := zerolog.Ctx(ctx.Context())
	logger.Debug().
		Str("_type", FinalizerNoop).
		Str("_name", f.name).
		Str("_id", f.id).
		Msg("Executing finalizer")

	return nil
}

func (f *noopFinalizer) WithConfig(stepID string, rawConfig map[string]any) (Finalizer, error) {
	if len(stepID) == 0 && len(rawConfig) == 0 {
		return f, nil
	}

	if len(rawConfig) != 0 {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "noop finalizer cannot be reconfigured").
			WithErrorContext(f)
	}

	fin := *f
	fin.id = stepID

	return &fin, nil
}

func (f *noopFinalizer) Name() string { return f.name }

func (f *noopFinalizer) ID() string { return f.id }

func (f *noopFinalizer) ContinueOnError() bool { return false }
