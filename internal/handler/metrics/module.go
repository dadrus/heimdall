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
	"os"
	"strings"
	"time"

	"github.com/justinas/alice"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/handler/fxlcm"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/methodfilter"
	"github.com/dadrus/heimdall/internal/x/loggeradapter"
)

var Module = fx.Invoke( // nolint: gochecknoglobals
	fx.Annotate(
		newLifecycleManager,
		fx.OnStart(func(ctx context.Context, lcm lifecycleManager) error { return lcm.Start(ctx) }),
		fx.OnStop(func(ctx context.Context, lcm lifecycleManager) error { return lcm.Stop(ctx) }),
	),
)

type lifecycleManager interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

type noopManager struct{}

func (noopManager) Start(context.Context) error { return nil }
func (noopManager) Stop(context.Context) error  { return nil }

// ErrLoggerFun is an adapter for promhttp Logger to log errors.
type ErrLoggerFun func(v ...interface{})

func (l ErrLoggerFun) Println(v ...interface{}) { l(v) }

func newLifecycleManager(app app.Context) lifecycleManager {
	conf := app.Config()
	logger := app.Logger()

	cfg := conf.Metrics
	exporterNames, _ := os.LookupEnv("OTEL_METRICS_EXPORTER")

	if !cfg.Enabled ||
		!strings.Contains(exporterNames, "prometheus") ||
		strings.Contains(exporterNames, "none") {
		logger.Info().Msg("Metrics service disabled")

		return noopManager{}
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics",
		alice.New(methodfilter.New(http.MethodGet)).
			Then(promhttp.InstrumentMetricHandler(
				prometheus.DefaultRegisterer,
				promhttp.HandlerFor(
					prometheus.DefaultGatherer,
					promhttp.HandlerOpts{
						Registry: prometheus.DefaultRegisterer,
						ErrorLog: ErrLoggerFun(func(v ...interface{}) { logger.Error().Msg(fmt.Sprint(v...)) }),
					},
				),
			)))

	return &fxlcm.LifecycleManager{
		ServiceName:    "Metrics",
		ServiceAddress: cfg.Address(),
		Server: &http.Server{
			Handler:        mux,
			ReadTimeout:    5 * time.Second,  // nolint: mnd
			WriteTimeout:   10 * time.Second, // nolint: mnd
			IdleTimeout:    90 * time.Second, // nolint: mnd
			MaxHeaderBytes: 4096,             // nolint: mnd
			ErrorLog:       loggeradapter.NewStdLogger(logger),
		},
		Logger: logger,
	}
}
