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

package module

import (
	"context"

	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/cache"
	_ "github.com/dadrus/heimdall/internal/cache/memory" // to register the memory cache
	_ "github.com/dadrus/heimdall/internal/cache/redis"  // to register the redis cache
	"github.com/dadrus/heimdall/internal/config"
)

//nolint:gochecknoglobals
var Module = fx.Provide(
	fx.Annotate(
		newCache,
		fx.OnStart(func(ctx context.Context, cch cache.Cache) error { return cch.Start(ctx) }),
		fx.OnStop(func(ctx context.Context, cch cache.Cache) error { return cch.Stop(ctx) }),
	),
)

func newCache(conf *config.Configuration, logger zerolog.Logger) (cache.Cache, error) {
	cch, err := cache.Open(conf.Cache.Type, conf.Cache.Config)
	if err != nil {
		logger.Info().Err(err).Msg("Could not initialize Cache")

		return nil, err
	}

	return cch, nil
}
