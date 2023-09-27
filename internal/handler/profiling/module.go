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
	"net/http"
	_ "net/http/pprof" //nolint:gosec
	"time"

	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/fxlcm"
	"github.com/dadrus/heimdall/internal/x/loggeradapter"
)

var Module = fx.Options( // nolint: gochecknoglobals
	fx.Invoke(registerHooks),
)

type hooksArgs struct {
	fx.In

	Lifecycle fx.Lifecycle
	Config    *config.Configuration
	Logger    zerolog.Logger
}

func registerHooks(args hooksArgs) {
	if !args.Config.Profiling.Enabled {
		args.Logger.Info().Msg("Profiling service disabled")

		return
	}

	slm := &fxlcm.LifecycleManager{
		Service: "Profiling",
		Server: &http.Server{
			Addr:              args.Config.Profiling.Address(),
			ReadHeaderTimeout: 5 * time.Second,  // nolint: gomnd
			IdleTimeout:       90 * time.Second, // nolint: gomnd
			ErrorLog:          loggeradapter.NewStdLogger(args.Logger),
		},
		Logger: args.Logger,
	}

	args.Lifecycle.Append(
		fx.Hook{
			OnStart: slm.Start,
			OnStop:  slm.Stop,
		},
	)
}
