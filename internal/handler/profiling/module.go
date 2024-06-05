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
	"net/http"
	_ "net/http/pprof" //nolint:gosec
	"time"

	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/fxlcm"
	"github.com/dadrus/heimdall/internal/x/loggeradapter"
)

type lifecycleManager interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

type noopManager struct{}

func (noopManager) Start(context.Context) error { return nil }
func (noopManager) Stop(context.Context) error  { return nil }

var Module = fx.Invoke( // nolint: gochecknoglobals
	fx.Annotate(
		newLifecycleManager,
		fx.OnStart(func(ctx context.Context, lcm lifecycleManager) error { return lcm.Start(ctx) }),
		fx.OnStop(func(ctx context.Context, lcm lifecycleManager) error { return lcm.Stop(ctx) }),
	),
)

func newLifecycleManager(conf *config.Configuration, logger zerolog.Logger) lifecycleManager {
	cfg := conf.Profiling
	if !cfg.Enabled {
		logger.Info().Msg("Profiling service disabled")

		return noopManager{}
	}

	return &fxlcm.LifecycleManager{
		ServiceName:    "Profiling",
		ServiceAddress: cfg.Address(),
		Logger:         logger,
		Server: &http.Server{
			ReadHeaderTimeout: 5 * time.Second,  // nolint: mnd
			IdleTimeout:       90 * time.Second, // nolint: mnd
			ErrorLog:          loggeradapter.NewStdLogger(logger),
		},
	}
}
