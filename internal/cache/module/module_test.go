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
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/cache/memory"
	"github.com/dadrus/heimdall/internal/cache/noop"
	"github.com/dadrus/heimdall/internal/config"
)

func TestNewCache(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		conf   *config.Configuration
		assert func(t *testing.T, err error, cch cache.Cache)
	}{
		{
			uc:   "empty cache type",
			conf: &config.Configuration{},
			assert: func(t *testing.T, err error, _ cache.Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, cache.ErrUnsupportedCacheType)
			},
		},
		{
			uc: "in memory cache",
			conf: &config.Configuration{
				Cache: config.CacheConfig{
					Type: "in-memory",
				},
			},
			assert: func(t *testing.T, err error, cch cache.Cache) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, &memory.Cache{}, cch)
			},
		},
		{
			uc: "Redis standalone cache without config",
			conf: &config.Configuration{
				Cache: config.CacheConfig{
					Type:   "redis",
					Config: map[string]any{},
				},
			},
			assert: func(t *testing.T, err error, _ cache.Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "'address' is a required field")
			},
		},
		{
			uc: "Redis cluster cache without config",
			conf: &config.Configuration{
				Cache: config.CacheConfig{
					Type:   "redis-cluster",
					Config: map[string]any{},
				},
			},
			assert: func(t *testing.T, err error, _ cache.Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "'nodes' must contain more than 0 items")
			},
		},
		{
			uc: "Redis sentinel cache without config",
			conf: &config.Configuration{
				Cache: config.CacheConfig{
					Type:   "redis-sentinel",
					Config: map[string]any{},
				},
			},
			assert: func(t *testing.T, err error, _ cache.Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "'nodes' must contain more than 0 items")
			},
		},
		{
			uc: "disabled cache type",
			conf: &config.Configuration{
				Cache: config.CacheConfig{
					Type: "noop",
				},
			},
			assert: func(t *testing.T, err error, cch cache.Cache) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, &noop.Cache{}, cch)
			},
		},
		{
			uc: "unknown cache type",
			conf: &config.Configuration{
				Cache: config.CacheConfig{
					Type: "foo",
				},
			},

			assert: func(t *testing.T, err error, _ cache.Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, cache.ErrUnsupportedCacheType)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			cch, err := newCache(tc.conf, log.Logger)

			// THEN
			tc.assert(t, err, cch)
		})
	}
}
