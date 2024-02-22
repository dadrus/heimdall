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
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/cache"
)

func TestCacheUsage(t *testing.T) {
	t.Parallel()

	db := miniredis.RunT(t)
	cch, err := NewStandaloneCache(map[string]any{
		"address":      db.Addr(),
		"client_cache": map[string]any{"disabled": true},
		"tls":          map[string]any{"disabled": true},
	})
	require.NoError(t, err)

	defer cch.Stop(context.TODO())

	for _, tc := range []struct {
		uc             string
		key            string
		configureCache func(*testing.T, cache.Cache)
		assert         func(t *testing.T, err error, data []byte)
	}{
		{
			uc:  "can retrieve not expired value",
			key: "foo",
			configureCache: func(t *testing.T, cch cache.Cache) {
				t.Helper()

				err := cch.Set(context.Background(), "foo", []byte("bar"), 10*time.Minute)
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
			configureCache: func(t *testing.T, cch cache.Cache) {
				t.Helper()

				err := cch.Set(context.Background(), "bar", []byte("baz"), 1*time.Millisecond)
				require.NoError(t, err)

				db.FastForward(200 * time.Millisecond)
			},
			assert: func(t *testing.T, err error, data []byte) {
				t.Helper()

				require.Error(t, err)
				assert.Nil(t, data)
			},
		},
		{
			uc:  "cannot retrieve not existing value",
			key: "baz",
			configureCache: func(t *testing.T, _ cache.Cache) {
				t.Helper()
			},
			assert: func(t *testing.T, err error, data []byte) {
				t.Helper()

				require.Error(t, err)
				assert.Nil(t, data)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			tc.configureCache(t, cch)

			data, err := cch.Get(context.Background(), tc.key)

			// THEN
			tc.assert(t, err, data)
		})
	}
}
