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
	"strconv"
	"sync/atomic"
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

func TestNoDeadlockOnSet(t *testing.T) {
	t.Parallel()

	key := "foo"
	done := make(chan struct{})

	cch, err := NewCache(nil, map[string]any{"entry_limit": 10})
	require.NoError(t, err)

	err = cch.Start(t.Context())
	require.NoError(t, err)

	defer cch.Stop(t.Context())

	go func() {
		_ = cch.Set(t.Context(), key, []byte("foo"), 1*time.Second)
		_ = cch.Set(t.Context(), key, []byte("bar"), 1*time.Second)

		close(done)
	}()

	select {
	case <-done:
		// test completed within time
	case <-time.After(250 * time.Millisecond):
		t.Fatal("test timed out - deadlock")
	}
}

func prepareCache(b *testing.B, size int) *Cache {
	c, err := NewCache(nil, nil)
	require.NoError(b, err)

	err = c.Start(b.Context())
	require.NoError(b, err)

	b.Cleanup(func() { _ = c.Stop(b.Context()) })

	value := []byte("value")

	for i := 0; i < size; i++ {
		key := "key-" + strconv.Itoa(i)

		err = c.Set(b.Context(), key, value, time.Minute)
		require.NoError(b, err)
	}

	return c.(*Cache)
}

func BenchmarkCache_Get_Empty(b *testing.B) {
	cch := prepareCache(b, 0)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = cch.Get(b.Context(), "missing-key")
	}
}

func BenchmarkCache_Get_1000(b *testing.B) {
	cacheCapacity := 1000
	cch := prepareCache(b, cacheCapacity)

	keys := make([]string, cacheCapacity)
	for i := 0; i < cacheCapacity; i++ {
		keys[i] = "key-" + strconv.Itoa(i)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = cch.Get(b.Context(), keys[i%cacheCapacity])
	}
}

func BenchmarkCache_Get_Parallel_1000(b *testing.B) {
	cacheCapacity := 1000
	cch := prepareCache(b, cacheCapacity)

	keys := make([]string, cacheCapacity)
	for i := range keys {
		keys[i] = "key-" + strconv.Itoa(i)
	}

	var idx atomic.Uint64

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			i := int(idx.Add(1)) % cacheCapacity
			_, _ = cch.Get(b.Context(), keys[i])
		}
	})
}

func BenchmarkCache_Get_10000(b *testing.B) {
	cacheCapacity := 10000
	cch := prepareCache(b, cacheCapacity)

	keys := make([]string, cacheCapacity)
	for i := 0; i < cacheCapacity; i++ {
		keys[i] = "key-" + strconv.Itoa(i)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = cch.Get(b.Context(), keys[i%cacheCapacity])
	}
}

func BenchmarkCache_Get_Parallel_10000(b *testing.B) {
	cacheCapacity := 10000
	cch := prepareCache(b, cacheCapacity)

	keys := make([]string, cacheCapacity)
	for i := range keys {
		keys[i] = "key-" + strconv.Itoa(i)
	}

	var idx atomic.Uint64

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			i := int(idx.Add(1)) % cacheCapacity
			_, _ = cch.Get(b.Context(), keys[i])
		}
	})
}

func BenchmarkCache_Set_New_1000(b *testing.B) {
	cacheCapacity := 1000
	cch := prepareCache(b, cacheCapacity)

	keys := make([]string, b.N)
	for i := 0; i < b.N; i++ {
		keys[i] = "new-key-" + strconv.Itoa(i)
	}

	value := []byte("new-value")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = cch.Set(b.Context(), keys[i], value, time.Minute)
	}
}

func BenchmarkCache_Set_Parallel_New_1000(b *testing.B) {
	cacheCapacity := 1000
	cch := prepareCache(b, cacheCapacity)

	keys := make([]string, b.N)
	for i := 0; i < b.N; i++ {
		keys[i] = "new-key-" + strconv.Itoa(i)
	}

	value := []byte("new-value")
	var idx atomic.Uint64

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			i := int(idx.Add(1)) - 1
			_ = cch.Set(b.Context(), keys[i], value, time.Minute)
		}
	})
}

func BenchmarkCache_Set_Existing_1000(b *testing.B) {
	cacheCapacity := 1000
	cch := prepareCache(b, cacheCapacity)

	keys := make([]string, cacheCapacity)
	for i := 0; i < cacheCapacity; i++ {
		keys[i] = "key-" + strconv.Itoa(i)
	}

	value := []byte("updated-value")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = cch.Set(b.Context(), keys[i%cacheCapacity], value, time.Minute)
	}
}

func BenchmarkCache_Set_Parallel_Existing_1000(b *testing.B) {
	cacheCapacity := 1000
	cch := prepareCache(b, cacheCapacity)

	keys := make([]string, cacheCapacity)
	for i := range keys {
		keys[i] = "key-" + strconv.Itoa(i)
	}

	value := []byte("updated-value")
	var idx atomic.Uint64

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			i := int(idx.Add(1)) % cacheCapacity
			_ = cch.Set(b.Context(), keys[i], value, time.Minute)
		}
	})
}

func BenchmarkCache_Set_New_10000(b *testing.B) {
	cacheCapacity := 10000
	cch := prepareCache(b, cacheCapacity)

	keys := make([]string, b.N)
	for i := 0; i < b.N; i++ {
		keys[i] = "new-key-" + strconv.Itoa(i)
	}

	value := []byte("new-value")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = cch.Set(b.Context(), keys[i], value, time.Minute)
	}
}

func BenchmarkCache_Set_Parallel_New_10000(b *testing.B) {
	cacheCapacity := 10000
	cch := prepareCache(b, cacheCapacity)

	keys := make([]string, b.N)
	for i := 0; i < b.N; i++ {
		keys[i] = "new-key-" + strconv.Itoa(i)
	}

	value := []byte("new-value")
	var idx atomic.Uint64

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			i := int(idx.Add(1)) - 1
			_ = cch.Set(b.Context(), keys[i], value, time.Minute)
		}
	})
}

func BenchmarkCache_Set_Existing_10000(b *testing.B) {
	cacheCapacity := 10000
	cch := prepareCache(b, cacheCapacity)

	keys := make([]string, cacheCapacity)
	for i := 0; i < cacheCapacity; i++ {
		keys[i] = "key-" + strconv.Itoa(i)
	}

	value := []byte("updated-value")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = cch.Set(b.Context(), keys[i%cacheCapacity], value, time.Minute)
	}
}

func BenchmarkCache_Set_Parallel_Existing_10000(b *testing.B) {
	cacheCapacity := 10000
	cch := prepareCache(b, cacheCapacity)

	keys := make([]string, cacheCapacity)
	for i := range keys {
		keys[i] = "key-" + strconv.Itoa(i)
	}

	value := []byte("updated-value")
	var idx atomic.Uint64

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			i := int(idx.Add(1)) % cacheCapacity
			_ = cch.Set(b.Context(), keys[i], value, time.Minute)
		}
	})
}
