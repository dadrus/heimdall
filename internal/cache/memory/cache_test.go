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

package memory

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCacheUsage(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc             string
		key            string
		configureCache func(t *testing.T, cache *InMemoryCache)
		assert         func(t *testing.T, err error, data any)
	}{
		{
			uc:  "can retrieve not expired value",
			key: "foo",
			configureCache: func(t *testing.T, cache *InMemoryCache) {
				t.Helper()

				err := cache.Set(context.TODO(), "foo", "bar", 10*time.Minute)
				require.NoError(t, err)
			},
			assert: func(t *testing.T, err error, data any) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "bar", data)
			},
		},
		{
			uc:  "cannot retrieve expired value",
			key: "bar",
			configureCache: func(t *testing.T, cache *InMemoryCache) {
				t.Helper()

				err := cache.Set(context.TODO(), "bar", "baz", 1*time.Microsecond)
				require.NoError(t, err)

				time.Sleep(200 * time.Millisecond)
			},
			assert: func(t *testing.T, err error, _ any) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrNoCacheEntry)
			},
		},
		{
			uc:  "cannot retrieve deleted value",
			key: "baz",
			configureCache: func(t *testing.T, cache *InMemoryCache) {
				t.Helper()

				err := cache.Set(context.TODO(), "baz", "bar", 1*time.Second)
				require.NoError(t, err)

				err = cache.Delete(context.TODO(), "baz")
				require.NoError(t, err)
			},
			assert: func(t *testing.T, err error, _ any) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrNoCacheEntry)
			},
		},
		{
			uc:  "cannot retrieve not existing value",
			key: "baz",
			configureCache: func(t *testing.T, _ *InMemoryCache) {
				t.Helper()
			},
			assert: func(t *testing.T, err error, _ any) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrNoCacheEntry)
			},
		},
		{
			uc:  "bad type on retrieving value",
			key: "zab",
			configureCache: func(t *testing.T, cache *InMemoryCache) {
				t.Helper()

				err := cache.Set(context.TODO(), "zab", 10, 1*time.Second)
				require.NoError(t, err)
			},
			assert: func(t *testing.T, err error, _ any) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrBadTargetType)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			var value string

			cache := New()

			// WHEN
			tc.configureCache(t, cache)

			err := cache.Get(context.TODO(), tc.key, &value)

			// THEN
			tc.assert(t, err, value)
		})
	}
}

func TestCacheGetNilTarget(t *testing.T) {
	t.Parallel()

	// WHEN
	err := New().Get(context.TODO(), "foo", nil)

	// THEN
	require.Error(t, err)
	require.ErrorIs(t, err, ErrBadTargetType)
}

func TestCacheExpiration(t *testing.T) {
	t.Parallel()

	cache := New()
	cache.Set(context.TODO(), "baz", "bar", 1*time.Second)

	hits := 0

	for i := 0; i < 8; i++ {
		time.Sleep(250 * time.Millisecond)

		var value string

		err := cache.Get(context.TODO(), "baz", &value)
		if err == nil {
			hits++
		}
	}

	assert.LessOrEqual(t, hits, 4)
}
