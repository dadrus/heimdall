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
)

// by intention. Used only during application bootstrap
//
//nolint:gochecknoinits
func init() {
	registerTypeFactory(
		func(app app.Context, id string, typ string, _ map[string]any) (bool, Finalizer, error) {
			if typ != FinalizerNoop {
				return false, nil, nil
			}

			return true, newNoopFinalizer(app, id), nil
		})
}

func newNoopFinalizer(app app.Context, id string) *noopFinalizer {
	logger := app.Logger()
	logger.Info().Str("_id", id).Msg("Creating noop finalizer")

	return &noopFinalizer{id: id}
}

type noopFinalizer struct {
	id string
}

func (f *noopFinalizer) Execute(ctx heimdall.Context, _ *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Str("_id", f.id).Msg("Finalizing using noop finalizer")

	return nil
}

func (f *noopFinalizer) WithConfig(map[string]any) (Finalizer, error) { return f, nil }

func (f *noopFinalizer) ID() string { return f.id }

func (f *noopFinalizer) ContinueOnError() bool { return false }
