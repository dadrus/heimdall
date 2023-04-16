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

package cache

import (
	"context"

	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/cache/memory"
	"github.com/dadrus/heimdall/internal/config"
)

// nolint
var Module = fx.Provide(
	fx.Annotate(
		newCache,
		fx.OnStart(func(ctx context.Context, cch Cache) error { return cch.Start(ctx) }),
		fx.OnStop(func(ctx context.Context, cch Cache) error { return cch.Stop(ctx) }),
	),
)

func newCache(conf *config.Configuration, logger zerolog.Logger) Cache {
	if len(conf.Cache.Type) == 0 {
		logger.Info().Msg("Instantiating in memory cache")

		return memory.New()
	}

	logger.Info().Msg("Cache is disabled")

	return noopCache{}
}
