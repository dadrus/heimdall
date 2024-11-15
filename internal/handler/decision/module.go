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

package decision

import (
	"context"

	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/fxlcm"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/watcher"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var Module = fx.Invoke( // nolint: gochecknoglobals
	fx.Annotate(
		newLifecycleManager,
		fx.OnStart(func(ctx context.Context, lcm *fxlcm.LifecycleManager) error { return lcm.Start(ctx) }),
		fx.OnStop(func(ctx context.Context, lcm *fxlcm.LifecycleManager) error { return lcm.Stop(ctx) }),
	),
)

func newLifecycleManager(
	conf *config.Configuration,
	logger zerolog.Logger,
	cch cache.Cache,
	exec rule.Executor,
	cw watcher.Watcher,
	es config.EnforcementSettings,
) *fxlcm.LifecycleManager {
	cfg := conf.Serve.Decision
	serviceName := "Decision"

	if cfg.TLS == nil {
		if es.EnforceIngressTLS {
			err := errorchain.NewWithMessage(heimdall.ErrConfiguration,
				"No TLS configured. "+
					"Please address this issue to ensure the protection of sensitive data during communication, "+
					"or disable this enforcement if necessary")
			logger.Fatal().Err(err).
				Str("_service", serviceName).
				Msg("Initialization failed")

			return nil
		}

		logger.Warn().
			Str("_service", serviceName).
			Msg("No TLS configured")
	}

	return &fxlcm.LifecycleManager{
		ServiceName:    serviceName,
		ServiceAddress: cfg.Address(),
		Server:         newService(conf, cch, logger, exec),
		Logger:         logger,
		TLSConf:        cfg.TLS,
		FileWatcher:    cw,
	}
}
