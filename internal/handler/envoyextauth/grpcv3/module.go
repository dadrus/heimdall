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

package grpcv3

import (
	"context"

	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/handler/fxlcm"
	"github.com/dadrus/heimdall/internal/rules/rule"
)

var Module = fx.Invoke( // nolint: gochecknoglobals
	fx.Annotate(
		newLifecycleManager,
		fx.OnStart(func(ctx context.Context, lcm *fxlcm.LifecycleManager) error { return lcm.Start(ctx) }),
		fx.OnStop(func(ctx context.Context, lcm *fxlcm.LifecycleManager) error { return lcm.Stop(ctx) }),
	),
)

func newLifecycleManager(app app.Context, exec rule.Executor, cch cache.Cache) *fxlcm.LifecycleManager {
	conf := app.Config()
	logger := app.Logger()
	cfg := conf.Serve

	return &fxlcm.LifecycleManager{
		ServiceName:    "Decision Envoy ExtAuth",
		ServiceAddress: cfg.Address(),
		Server: &adapter{
			s: newService(conf, cch, logger, exec),
		},
		Logger:      logger,
		TLSConf:     cfg.TLS,
		FileWatcher: app.Watcher(),
	}
}
