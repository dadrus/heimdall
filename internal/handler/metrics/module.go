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
	"time"

	"github.com/justinas/alice"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
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
	Start(context.Context) error
	Stop(context.Context) error
}

type noopManager struct{}

func (noopManager) Start(context.Context) error { return nil }
func (noopManager) Stop(context.Context) error  { return nil }

// ErrLoggerFun is an adapter for promhttp Logger to log errors.
type ErrLoggerFun func(v ...interface{})

func (l ErrLoggerFun) Println(v ...interface{}) { l(v) }

type hooksArgs struct {
	fx.In

	Registerer prometheus.Registerer
	Gatherer   prometheus.Gatherer
	Config     *config.Configuration
	Logger     zerolog.Logger
}

func newLifecycleManager(args hooksArgs) lifecycleManager {
	cfg := args.Config.Metrics
	if !cfg.Enabled {
		args.Logger.Info().Msg("Metrics service disabled")

		return noopManager{}
	}

	mux := http.NewServeMux()
	mux.Handle(cfg.MetricsPath,
		alice.New(methodfilter.New(http.MethodGet)).
			Then(promhttp.InstrumentMetricHandler(
				args.Registerer,
				promhttp.HandlerFor(
					args.Gatherer,
					promhttp.HandlerOpts{
						Registry: args.Registerer,
						ErrorLog: ErrLoggerFun(func(v ...interface{}) { args.Logger.Error().Msg(fmt.Sprint(v...)) }),
					},
				),
			)))

	return &fxlcm.LifecycleManager{
		ServiceName:    "Metrics",
		ServiceAddress: cfg.Address(),
		Server: &http.Server{
			Handler:        mux,
			ReadTimeout:    5 * time.Second,  // nolint: gomnd
			WriteTimeout:   10 * time.Second, // nolint: gomnd
			IdleTimeout:    90 * time.Second, // nolint: gomnd
			MaxHeaderBytes: 4096,             // nolint: gomnd
			ErrorLog:       loggeradapter.NewStdLogger(args.Logger),
		},
		Logger: args.Logger,
	}
}
