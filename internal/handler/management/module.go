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

package management

import (
	"context"
	"errors"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/listener"
	"github.com/dadrus/heimdall/internal/heimdall"
)

var Module = fx.Options( // nolint: gochecknoglobals
	fx.Invoke(registerHooks),
)

type hooksArgs struct {
	fx.In

	Lifecycle  fx.Lifecycle
	Config     *config.Configuration
	Logger     zerolog.Logger
	Registerer prometheus.Registerer
	Signer     heimdall.JWTSigner
}

func registerHooks(args hooksArgs) {
	ln, err := listener.New("tcp", args.Config.Serve.Management)
	if err != nil {
		args.Logger.Fatal().Err(err).Msg("Could not create listener for the Management service")

		return
	}

	srv := newService(args.Config, args.Registerer, args.Logger, args.Signer)

	args.Lifecycle.Append(
		fx.Hook{
			OnStart: func(ctx context.Context) error {
				go func() {
					args.Logger.Info().Str("_address", ln.Addr().String()).Msg("Management service starts listening")

					if err = srv.Serve(ln); err != nil {
						if !errors.Is(err, http.ErrServerClosed) {
							args.Logger.Fatal().Err(err).Msg("Could not start Management service")
						}
					}
				}()

				return nil
			},
			OnStop: func(ctx context.Context) error {
				args.Logger.Info().Msg("Tearing down Management service")

				return srv.Shutdown(ctx)
			},
		},
	)
}
