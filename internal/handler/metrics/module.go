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

package metrics

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/justinas/alice"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/listener"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/methodfilter"
	"github.com/dadrus/heimdall/internal/x/loggeradapter"
)

var Module = fx.Options( // nolint: gochecknoglobals
	fx.Invoke(registerHooks),
)

// ErrLoggerFun is an adapter for promhttp Logger to log errors.
type ErrLoggerFun func(v ...interface{})

func (l ErrLoggerFun) Println(v ...interface{}) { l(v) }

type hooksArgs struct {
	fx.In

	Lifecycle  fx.Lifecycle
	Registerer prometheus.Registerer
	Gatherer   prometheus.Gatherer
	Config     *config.Configuration
	Logger     zerolog.Logger
}

func registerHooks(args hooksArgs) {
	if !args.Config.Metrics.Enabled {
		args.Logger.Info().Msg("Metrics service disabled")

		return
	}

	metricsHandler := promhttp.InstrumentMetricHandler(
		args.Registerer,
		promhttp.HandlerFor(
			args.Gatherer,
			promhttp.HandlerOpts{
				Registry: args.Registerer,
				ErrorLog: ErrLoggerFun(func(v ...interface{}) { args.Logger.Error().Msg(fmt.Sprint(v...)) }),
			},
		),
	)

	mux := http.NewServeMux()
	mux.Handle(args.Config.Metrics.MetricsPath,
		alice.New(methodfilter.New(http.MethodGet)).
			Then(metricsHandler))

	srv := &http.Server{
		Handler:        mux,
		Addr:           args.Config.Metrics.Address(),
		ReadTimeout:    5 * time.Second,  // nolint: gomnd
		WriteTimeout:   10 * time.Second, // nolint: gomnd
		IdleTimeout:    90 * time.Second, // nolint: gomnd
		MaxHeaderBytes: 4096,             // nolint: gomnd
		ErrorLog:       loggeradapter.NewStdLogger(args.Logger),
	}

	args.Lifecycle.Append(
		fx.Hook{
			OnStart: func(ctx context.Context) error {
				ln, err := listener.New("tcp", args.Config.Metrics.Address(), nil)
				if err != nil {
					args.Logger.Fatal().Err(err).Msg("Could not create listener for the Metrics service")

					return err
				}

				go func() {
					args.Logger.Info().Str("_address", ln.Addr().String()).Msg("Metrics service starts listening")

					if err = srv.Serve(ln); err != nil {
						if !errors.Is(err, http.ErrServerClosed) {
							args.Logger.Fatal().Err(err).Msg("Could not start Metrics service")
						}
					}
				}()

				return nil
			},
			OnStop: func(ctx context.Context) error {
				args.Logger.Info().Msg("Tearing down Metrics service")

				return srv.Shutdown(ctx)
			},
		},
	)
}
