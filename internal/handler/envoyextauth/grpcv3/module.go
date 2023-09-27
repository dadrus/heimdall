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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/fxlcm"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/rule"
)

var Module = fx.Options( // nolint: gochecknoglobals
	fx.Invoke(registerHooks),
)

type hooksArgs struct {
	fx.In

	Lifecycle  fx.Lifecycle
	Config     *config.Configuration
	Logger     zerolog.Logger
	Exec       rule.Executor
	Signer     heimdall.JWTSigner
	Registerer prometheus.Registerer
	Cache      cache.Cache
}

func registerHooks(args hooksArgs) {
	cfg := args.Config.Serve.Decision
	slm := &fxlcm.LifecycleManager{
		ServiceName:    "Decision Envoy ExtAuth",
		ServiceAddress: cfg.Address(),
		Server: &adapter{
			s: newService(args.Config, args.Registerer, args.Cache, args.Logger, args.Exec, args.Signer),
		},
		Logger:  args.Logger,
		TLSConf: cfg.TLS,
	}

	args.Lifecycle.Append(
		fx.Hook{
			OnStart: slm.Start,
			OnStop:  slm.Stop,
		},
	)
}
