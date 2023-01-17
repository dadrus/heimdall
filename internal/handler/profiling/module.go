// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
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

package profiling

import (
	"context"

	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
)

var Module = fx.Options( // nolint: gochecknoglobals
	fx.Invoke(registerHooks),
)

type hooksArgs struct {
	fx.In

	Lifecycle fx.Lifecycle
	Config    *config.Configuration
	Logger    zerolog.Logger
}

func registerHooks(args hooksArgs) {
	if !args.Config.Profiling.Enabled {
		return
	}

	app := newApp()

	args.Lifecycle.Append(
		fx.Hook{
			OnStart: func(ctx context.Context) error {
				go func() {
					addr := args.Config.Profiling.Address()
					args.Logger.Info().Str("_address", addr).Msg("Profiling service starts listening")
					if err := app.Listen(addr); err != nil {
						args.Logger.Fatal().Err(err).Msg("Could not start Profiling service")
					}
				}()

				return nil
			},
			OnStop: func(ctx context.Context) error {
				args.Logger.Info().Msg("Tearing down Profiling service")

				return app.Shutdown()
			},
		},
	)
}
