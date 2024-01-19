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
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/cache/memory"
	"github.com/dadrus/heimdall/internal/cache/noop"
	"github.com/dadrus/heimdall/internal/cache/redis"
	"github.com/dadrus/heimdall/internal/config"
)

func TestNewCache(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		conf   *config.Configuration
		assert func(t *testing.T, cch cache.Cache)
	}{
		{
			uc:   "empty cache type",
			conf: &config.Configuration{},
			assert: func(t *testing.T, cch cache.Cache) {
				t.Helper()

				assert.IsType(t, &noop.Cache{}, cch)
			},
		},
		{
			uc: "in memory cache",
			conf: &config.Configuration{
				Cache: config.CacheConfig{
					Type: "memory",
				},
			},
			assert: func(t *testing.T, cch cache.Cache) {
				t.Helper()

				assert.IsType(t, &memory.Cache{}, cch)
			},
		},

		{
			uc: "Redis cache without DSN",
			conf: &config.Configuration{
				Cache: config.CacheConfig{
					Type:   "redis",
					Config: map[string]any{},
				},
			},
			assert: func(t *testing.T, cch cache.Cache) {
				t.Helper()

				assert.IsType(t, &noop.Cache{}, cch)
			},
		},
		{
			uc: "Redis cache",
			conf: &config.Configuration{
				Cache: config.CacheConfig{
					Type:   "redis",
					Config: map[string]any{"Addr": "localhost.com:6379"},
				},
			},
			assert: func(t *testing.T, cch cache.Cache) {
				t.Helper()

				assert.IsType(t, &redis.SimpleCache{}, cch)
			},
		},
		{
			uc: "disabled cache type",
			conf: &config.Configuration{
				Cache: config.CacheConfig{
					Type: "noop",
				},
			},
			assert: func(t *testing.T, cch cache.Cache) {
				t.Helper()

				assert.IsType(t, noop.Cache{}, cch)
			},
		},
		{
			uc: "unknown cache type",
			conf: &config.Configuration{
				Cache: config.CacheConfig{
					Type: "foo",
				},
			},

			assert: func(t *testing.T, cch cache.Cache) {
				t.Helper()

				assert.IsType(t, &noop.Cache{}, cch)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			cch, _ := newCache(tc.conf, log.Logger)

			// THEN
			tc.assert(t, cch)
		})
	}
}
