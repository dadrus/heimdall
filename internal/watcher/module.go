// Copyright 2024 Dimitrij Drus <dadrus@gmx.de>
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

package watcher

import (
	"context"

	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
)

// Module is used on app bootstrap.
// nolint: gochecknoglobals
var Module = fx.Options(
	fx.Provide(
		fx.Annotate(
			func(cfg *config.Configuration, logger zerolog.Logger) (Watcher, error) {
				if cfg.SecretsReloadEnabled {
					return newWatcher(logger)
				}

				return &NoopWatcher{}, nil
			},
			// nolint: forcetypeassert
			fx.OnStart(func(ctx context.Context, w Watcher) error {
				w.(controller).start(ctx)

				return nil
			}),
			// nolint: forcetypeassert
			fx.OnStop(func(ctx context.Context, w Watcher) error { return w.(controller).stop(ctx) }),
		),
	),
)
