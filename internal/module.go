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

package internal

import (
	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/cache/module"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/management"
	"github.com/dadrus/heimdall/internal/handler/metrics"
	"github.com/dadrus/heimdall/internal/handler/profiling"
	"github.com/dadrus/heimdall/internal/logging"
	"github.com/dadrus/heimdall/internal/otel"
	"github.com/dadrus/heimdall/internal/rules"
	"github.com/dadrus/heimdall/internal/rules/mechanisms"
	"github.com/dadrus/heimdall/internal/signer"
	"github.com/dadrus/heimdall/version"
)

var Module = fx.Options( //nolint:gochecknoglobals
	config.Module,
	logging.Module,
	fx.Invoke(func(logger zerolog.Logger) {
		logger.Info().Str("_version", version.Version).Msg("Starting heimdall")
	}),
	otel.Module,
	module.Module,
	signer.Module,
	mechanisms.Module,
	rules.Module,
	management.Module,
	metrics.Module,
	profiling.Module,
)
