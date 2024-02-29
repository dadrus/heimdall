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

	"github.com/dadrus/heimdall/internal/cache"
)

func TestMemoryCacheUsage(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc             string
		key            string
		configureCache func(t *testing.T, cache cache.Cache)
		assert         func(t *testing.T, err error, data []byte)
	}{
		{
			uc:  "can retrieve not expired value",
			key: "foo",
			configureCache: func(t *testing.T, cache cache.Cache) {
				t.Helper()

				err := cache.Set(context.TODO(), "foo", []byte("bar"), 10*time.Minute)
				require.NoError(t, err)
			},
			assert: func(t *testing.T, err error, data []byte) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, []byte("bar"), data)
			},
		},
		{
			uc:  "cannot retrieve expired value",
			key: "bar",
			configureCache: func(t *testing.T, cache cache.Cache) {
				t.Helper()

				err := cache.Set(context.TODO(), "bar", []byte("baz"), 1*time.Microsecond)
				require.NoError(t, err)

				time.Sleep(200 * time.Millisecond)
			},
			assert: func(t *testing.T, err error, _ []byte) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrNoCacheEntry)
			},
		},
		{
			uc:  "cannot retrieve not existing value",
			key: "baz",
			configureCache: func(t *testing.T, _ cache.Cache) {
				t.Helper()
			},
			assert: func(t *testing.T, err error, _ []byte) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrNoCacheEntry)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			cache, _ := NewCache(nil, nil)

			// WHEN
			tc.configureCache(t, cache)

			value, err := cache.Get(context.TODO(), tc.key)

			// THEN
			tc.assert(t, err, value)
		})
	}
}

func TestMemoryCacheExpiration(t *testing.T) {
	t.Parallel()

	cache, _ := NewCache(nil, nil)
	cache.Set(context.TODO(), "baz", []byte("bar"), 1*time.Second)

	hits := 0

	for i := 0; i < 8; i++ {
		time.Sleep(250 * time.Millisecond)

		value, err := cache.Get(context.TODO(), "baz")
		if err == nil {
			hits++

			assert.Equal(t, []byte("bar"), value)
		}
	}

	assert.LessOrEqual(t, hits, 4)
}
