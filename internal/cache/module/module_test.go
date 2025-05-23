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

package module

import (
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/cache/memory"
	"github.com/dadrus/heimdall/internal/cache/noop"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/validation"
)

func TestNewCache(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		conf   *config.Configuration
		assert func(t *testing.T, err error, cch cache.Cache)
	}{
		"empty cache type": {
			conf: &config.Configuration{},
			assert: func(t *testing.T, err error, _ cache.Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, cache.ErrUnsupportedCacheType)
			},
		},
		"in memory cache": {
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
		"Redis standalone cache without config": {
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
		"Redis cluster cache without config": {
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
		"Redis sentinel cache without config": {
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
		"disabled cache type": {
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
		"unknown cache type": {
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
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			validator, err := validation.NewValidator(
				validation.WithTagValidator(config.EnforcementSettings{}),
			)
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Config().Return(tc.conf)
			appCtx.EXPECT().Logger().Return(log.Logger)
			appCtx.EXPECT().Validator().Maybe().Return(validator)

			// WHEN
			cch, err := newCache(appCtx)

			// THEN
			tc.assert(t, err, cch)
		})
	}
}
