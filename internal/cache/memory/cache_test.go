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
)

func TestMemoryCacheUsage(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc             string
		key            string
		configureCache func(t *testing.T, cache *Cache)
		assert         func(t *testing.T, data any)
	}{
		{
			uc:  "can retrieve not expired value",
			key: "foo",
			configureCache: func(t *testing.T, cache *Cache) {
				t.Helper()

				cache.Set(context.TODO(), "foo", "bar", 10*time.Minute)
			},
			assert: func(t *testing.T, data any) {
				t.Helper()

				assert.Equal(t, "bar", data)
			},
		},
		{
			uc:  "cannot retrieve expired value",
			key: "bar",
			configureCache: func(t *testing.T, cache *Cache) {
				t.Helper()

				cache.Set(context.TODO(), "bar", "baz", 1*time.Microsecond)

				time.Sleep(200 * time.Millisecond)
			},
			assert: func(t *testing.T, data any) {
				t.Helper()

				assert.Nil(t, data)
			},
		},
		{
			uc:  "cannot retrieve deleted value",
			key: "baz",
			configureCache: func(t *testing.T, cache *Cache) {
				t.Helper()

				cache.Set(context.TODO(), "baz", "bar", 1*time.Second)
				cache.Delete(context.TODO(), "baz")
			},
			assert: func(t *testing.T, data any) {
				t.Helper()

				assert.Nil(t, data)
			},
		},
		{
			uc:  "cannot retrieve not existing value",
			key: "baz",
			configureCache: func(t *testing.T, cache *Cache) {
				t.Helper()
			},
			assert: func(t *testing.T, data any) {
				t.Helper()

				assert.Nil(t, data)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			cache := NewCache()

			// WHEN
			tc.configureCache(t, cache)

			data := cache.Get(context.TODO(), tc.key)

			// THEN
			tc.assert(t, data)
		})
	}
}

func TestMemoryCacheExpiration(t *testing.T) {
	t.Parallel()

	cache := NewCache()
	cache.Set(context.TODO(), "baz", "bar", 1*time.Second)

	hits := 0

	for i := 0; i < 8; i++ {
		time.Sleep(250 * time.Millisecond)

		item := cache.Get(context.TODO(), "baz")
		if item != nil {
			hits++
		}
	}

	assert.LessOrEqual(t, hits, 4)
}
