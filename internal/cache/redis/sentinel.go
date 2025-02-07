// Copyright 2024 Dimitrij Drus <dadrus@gmx.de>
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

package redis

import (
	"time"

	"github.com/redis/rueidis"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/cache"
)

// by intention. Used only during application bootstrap.
func init() { // nolint: gochecknoinits
	cache.Register("redis-sentinel", cache.FactoryFunc(NewSentinelCache))
}

func NewSentinelCache(app app.Context, conf map[string]any) (cache.Cache, error) {
	type Config struct {
		baseConfig `mapstructure:",squash"`

		Nodes  []string `mapstructure:"nodes"  validate:"gt=0,dive,required"`
		Master string   `mapstructure:"master" validate:"required"`
		DB     int      `mapstructure:"db"`
	}

	cfg := Config{
		baseConfig: baseConfig{ClientCache: clientCache{TTL: 5 * time.Minute}}, //nolint:mnd
	}

	err := decodeConfig(app.Validator(), conf, &cfg)
	if err != nil {
		return nil, err
	}

	opts, err := cfg.clientOptions(app, "redis-sentinel")
	if err != nil {
		return nil, err
	}

	opts.InitAddress = cfg.Nodes
	opts.ShuffleInit = true
	opts.SelectDB = cfg.DB
	opts.Sentinel = rueidis.SentinelOption{
		MasterSet: cfg.Master,
	}

	return newRedisCache(opts, cfg.ClientCache.TTL), nil
}
