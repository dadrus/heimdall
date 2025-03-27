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
	"fmt"
	"testing"
	"time"

	"github.com/DmitriyVTitov/size"
	"github.com/inhies/go-bytesize"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestNewCache(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		config []byte
		err    error
	}{
		"empty configuration": {
			config: []byte{},
		},
		"unknown config settings": {
			config: []byte(`foo: bar`),
			err:    heimdall.ErrConfiguration,
		},
		"max memory is configured": {
			config: []byte(`memory_limit: 10MB`),
		},
		"max entries is configured": {
			config: []byte(`entry_limit: 10`),
		},
		"both, max entries and max memory are configured": {
			config: []byte(`
entry_limit: 10
memory_limit: 100MB
`),
		},
	} {
		t.Run(uc, func(t *testing.T) {
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			_, err = NewCache(nil, conf)

			if tc.err != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestMemoryCacheUsage(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		key            string
		configureCache func(t *testing.T, cache cache.Cache)
		assert         func(t *testing.T, err error, data []byte)
	}{
		"can retrieve not expired value": {
			key: "foo",
			configureCache: func(t *testing.T, cache cache.Cache) {
				t.Helper()

				err := cache.Set(t.Context(), "foo", []byte("bar"), 10*time.Minute)
				require.NoError(t, err)
			},
			assert: func(t *testing.T, err error, data []byte) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, []byte("bar"), data)
			},
		},
		"cannot retrieve expired value": {
			key: "bar",
			configureCache: func(t *testing.T, cache cache.Cache) {
				t.Helper()

				err := cache.Set(t.Context(), "bar", []byte("baz"), 1*time.Microsecond)
				require.NoError(t, err)

				time.Sleep(200 * time.Millisecond)
			},
			assert: func(t *testing.T, err error, _ []byte) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrNoCacheEntry)
			},
		},
		"cannot retrieve not existing value": {
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
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			cch, err := NewCache(nil, map[string]any{})
			require.NoError(t, err)

			err = cch.Start(t.Context())
			require.NoError(t, err)

			defer cch.Stop(t.Context())

			// WHEN
			tc.configureCache(t, cch)

			value, err := cch.Get(t.Context(), tc.key)

			// THEN
			tc.assert(t, err, value)
		})
	}
}

func TestMemoryCacheExpiration(t *testing.T) {
	t.Parallel()

	cch, err := NewCache(nil, map[string]any{})
	require.NoError(t, err)

	err = cch.Start(t.Context())
	require.NoError(t, err)

	defer cch.Stop(t.Context())

	err = cch.Set(t.Context(), "baz", []byte("bar"), 1*time.Second)
	require.NoError(t, err)

	hits := 0

	for range 8 {
		time.Sleep(250 * time.Millisecond)

		value, err := cch.Get(t.Context(), "baz")
		if err == nil {
			hits++

			assert.Equal(t, []byte("bar"), value)
		}
	}

	assert.LessOrEqual(t, hits, 4)
}

func TestMemoryLimit(t *testing.T) {
	t.Parallel()

	cch, err := NewCache(nil, map[string]any{"memory_limit": "2MB"})
	require.NoError(t, err)

	err = cch.Start(t.Context())
	require.NoError(t, err)

	defer cch.Stop(t.Context())

	for i := range 1000 {
		key := fmt.Sprintf("foo%d", i)
		data := make([]byte, 100*bytesize.KB)

		err = cch.Set(t.Context(), key, data, 15*time.Second)
		require.NoError(t, err)
	}

	finalSize := size.Of(cch)
	assert.LessOrEqual(t, finalSize, int(2*bytesize.MB))
}

func TestEntryLimit(t *testing.T) {
	t.Parallel()

	cch, err := NewCache(nil, map[string]any{"entry_limit": 10})
	require.NoError(t, err)

	err = cch.Start(t.Context())
	require.NoError(t, err)

	defer cch.Stop(t.Context())

	for i := range 1000 {
		key := fmt.Sprintf("foo%d", i)
		data := make([]byte, 100*bytesize.KB)

		err = cch.Set(t.Context(), key, data, 15*time.Second)
		require.NoError(t, err)
	}

	// measuring the entries via memory size
	finalSize := size.Of(cch)
	assert.LessOrEqual(t, finalSize, int(1100*bytesize.KB))
}
