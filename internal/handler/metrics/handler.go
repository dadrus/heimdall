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

package metrics

import (
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

// ErrLoggerFun is an adapter for promhttp Logger to log errors.
type ErrLoggerFun func(v ...interface{})

func (l ErrLoggerFun) Println(v ...interface{}) { l(v) }

type Handler struct{}

type handlerArgs struct {
	fx.In

	App        *fiber.App `name:"metrics"`
	Registerer prometheus.Registerer
	Gatherer   prometheus.Gatherer
	Config     *config.Configuration
	Logger     zerolog.Logger
}

func newHandler(args handlerArgs) (*Handler, error) {
	handler := &Handler{}

	handler.registerRoutes(
		args.App.Group(args.Config.Metrics.Prometheus.MetricsPath),
		args.Logger,
		promhttp.InstrumentMetricHandler(
			args.Registerer,
			promhttp.HandlerFor(
				args.Gatherer,
				promhttp.HandlerOpts{
					Registry: args.Registerer,
					ErrorLog: ErrLoggerFun(func(v ...interface{}) { args.Logger.Error().Msg(fmt.Sprint(v...)) }),
				},
			),
		),
	)

	return handler, nil
}

func (h *Handler) registerRoutes(router fiber.Router, logger zerolog.Logger, handler http.Handler) {
	logger.Debug().Msg("Registering Metrics service routes")

	router.Get("", adaptor.HTTPHandler(handler))
}
