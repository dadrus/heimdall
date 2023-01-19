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
	"fmt"
	"net/http"

	"github.com/gofiber/adaptor/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
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

	app := fiber.New(fiber.Config{
		AppName:               "Heimdall's Metrics endpoint",
		DisableStartupMessage: true,
	})

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

	registerRoutes(app.Group(args.Config.Metrics.MetricsPath), args.Logger, metricsHandler)

	args.Lifecycle.Append(
		fx.Hook{
			OnStart: func(ctx context.Context) error {
				go func() {
					addr := args.Config.Metrics.Address()
					args.Logger.Info().Str("_address", addr).Msg("Metrics service starts listening")
					if err := app.Listen(addr); err != nil {
						args.Logger.Fatal().Err(err).Msg("Could not start Metrics service")
					}
				}()

				return nil
			},
			OnStop: func(ctx context.Context) error {
				args.Logger.Info().Msg("Tearing down Metrics service")

				return app.Shutdown()
			},
		},
	)
}

func registerRoutes(router fiber.Router, logger zerolog.Logger, handler http.Handler) {
	logger.Debug().Msg("Registering Metrics service routes")

	router.Get("", adaptor.HTTPHandler(handler))
}
