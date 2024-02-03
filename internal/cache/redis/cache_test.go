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
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestNewCache(t *testing.T) {
	t.Parallel()

	db := miniredis.RunT(t)

	for _, tc := range []struct {
		uc     string
		config []byte
		assert func(t *testing.T, err error, cch *Cache)
	}{
		{
			uc:     "empty config",
			config: []byte(``),
			assert: func(t *testing.T, err error, cch *Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'addrs' must contain more than 0 items")
			},
		},
		{
			uc:     "empty address provided",
			config: []byte(`addrs: [""]`),
			assert: func(t *testing.T, err error, cch *Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'addrs'[0] is a required field")
			},
		},
		{
			uc:     "config contains unsupported properties",
			config: []byte(`foo: bar`),
			assert: func(t *testing.T, err error, cch *Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed decoding redis cache config")
			},
		},
		{
			uc:     "not existing address provided",
			config: []byte(`addrs: ["foo.local:12345"]`),
			assert: func(t *testing.T, err error, cch *Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				require.ErrorContains(t, err, "failed creating redis cache client")
			},
		},
		{
			uc:     "successful cache creation",
			config: []byte(fmt.Sprintf("{addrs: [%s], client_cache: {disabled: true}}", db.Addr())),
			assert: func(t *testing.T, err error, cch *Cache) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, cch)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			cch, err := NewCache(conf)
			if err == nil {
				defer cch.Stop(context.TODO())
			}

			// THEN
			tc.assert(t, err, cch)
		})
	}
}

func TestCacheUsage(t *testing.T) {
	t.Parallel()

	db := miniredis.RunT(t)
	cch, err := NewCache(map[string]any{
		"addrs":        []string{db.Addr()},
		"client_cache": map[string]any{"disabled": true},
	})
	require.NoError(t, err)

	defer cch.Stop(context.TODO())

	for _, tc := range []struct {
		uc             string
		key            string
		configureCache func(*testing.T, *Cache)
		assert         func(t *testing.T, data any)
	}{
		{
			uc:  "can retrieve not expired value",
			key: "foo",
			configureCache: func(t *testing.T, cch *Cache) {
				t.Helper()

				cch.Set(context.Background(), "foo", "bar", 10*time.Minute)
			},
			assert: func(t *testing.T, data any) {
				t.Helper()

				assert.Equal(t, "bar", data)
			},
		},
		{
			uc:  "cannot retrieve expired value",
			key: "bar",
			configureCache: func(t *testing.T, cch *Cache) {
				t.Helper()

				cch.Set(context.Background(), "bar", "baz", 1*time.Millisecond)

				db.FastForward(200 * time.Millisecond)
			},
			assert: func(t *testing.T, data any) {
				t.Helper()

				assert.Nil(t, data)
			},
		},
		{
			uc:  "cannot retrieve deleted value",
			key: "baz",
			configureCache: func(t *testing.T, cch *Cache) {
				t.Helper()

				cch.Set(context.Background(), "baz", "bar", 1*time.Second)
				cch.Delete(context.Background(), "baz")
			},
			assert: func(t *testing.T, data any) {
				t.Helper()

				assert.Nil(t, data)
			},
		},
		{
			uc:  "cannot retrieve not existing value",
			key: "baz",
			configureCache: func(t *testing.T, cch *Cache) {
				t.Helper()
			},
			assert: func(t *testing.T, data any) {
				t.Helper()

				assert.Nil(t, data)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			tc.configureCache(t, cch)

			data := cch.Get(context.Background(), tc.key)

			// THEN
			tc.assert(t, data)
		})
	}
}
