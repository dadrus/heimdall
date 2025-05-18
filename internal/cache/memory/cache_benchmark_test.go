// Copyright 2025 Dimitrij Drus <dadrus@gmx.de>
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
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func prepareCache(b *testing.B, size uint64) *Cache {
	b.Helper()

	cch, err := NewCache(nil, nil)
	require.NoError(b, err)

	err = cch.Start(b.Context())
	require.NoError(b, err)

	b.Cleanup(func() { _ = cch.Stop(b.Context()) })

	value := []byte("value")

	for i := range size {
		key := "key-" + strconv.FormatUint(i, 10)

		err = cch.Set(b.Context(), key, value, time.Minute)
		require.NoError(b, err)
	}

	return cch.(*Cache)
}

func BenchmarkCache_Get_Empty(b *testing.B) {
	cch := prepareCache(b, 0)

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_, _ = cch.Get(b.Context(), "missing-key")
	}
}

func BenchmarkCache_Get_1000(b *testing.B) {
	cacheCapacity := uint64(1000)
	cch := prepareCache(b, cacheCapacity)

	keys := make([]string, cacheCapacity)
	for i := range cacheCapacity {
		keys[i] = "key-" + strconv.FormatUint(i, 10)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := range b.N {
		idx := i % len(keys)
		_, _ = cch.Get(b.Context(), keys[idx])
	}
}

func BenchmarkCache_Get_Parallel_1000(b *testing.B) {
	var idx atomic.Uint64

	cacheCapacity := uint64(1000)
	cch := prepareCache(b, cacheCapacity)

	keys := make([]string, cacheCapacity)
	for i := range keys {
		keys[i] = "key-" + strconv.Itoa(i)
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			i := idx.Add(1) % cacheCapacity
			_, _ = cch.Get(b.Context(), keys[i])
		}
	})
}

func BenchmarkCache_Get_10000(b *testing.B) {
	cacheCapacity := uint64(10000)
	cch := prepareCache(b, cacheCapacity)

	keys := make([]string, cacheCapacity)
	for i := range cacheCapacity {
		keys[i] = "key-" + strconv.FormatUint(i, 10)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := range b.N {
		idx := i % len(keys)
		_, _ = cch.Get(b.Context(), keys[idx])
	}
}

func BenchmarkCache_Get_Parallel_10000(b *testing.B) {
	var idx atomic.Uint64

	cacheCapacity := uint64(10000)
	cch := prepareCache(b, cacheCapacity)

	keys := make([]string, cacheCapacity)
	for i := range keys {
		keys[i] = "key-" + strconv.Itoa(i)
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			i := idx.Add(1) % cacheCapacity
			_, _ = cch.Get(b.Context(), keys[i])
		}
	})
}

func BenchmarkCache_Set_New_1000(b *testing.B) {
	cacheCapacity := uint64(1000)
	cch := prepareCache(b, cacheCapacity)
	value := []byte("new-value")

	keys := make([]string, b.N)
	for i := range b.N {
		keys[i] = "new-key-" + strconv.Itoa(i)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := range b.N {
		_ = cch.Set(b.Context(), keys[i], value, time.Minute)
	}
}

func BenchmarkCache_Set_Parallel_New_1000(b *testing.B) {
	var idx atomic.Uint64

	cacheCapacity := uint64(1000)
	cch := prepareCache(b, cacheCapacity)
	value := []byte("new-value")

	keys := make([]string, b.N)
	for i := range b.N {
		keys[i] = "new-key-" + strconv.Itoa(i)
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			i := idx.Add(1) - 1
			_ = cch.Set(b.Context(), keys[i], value, time.Minute)
		}
	})
}

func BenchmarkCache_Set_Existing_1000(b *testing.B) {
	cacheCapacity := uint64(1000)
	cch := prepareCache(b, cacheCapacity)
	value := []byte("updated-value")

	keys := make([]string, cacheCapacity)
	for i := range cacheCapacity {
		keys[i] = "key-" + strconv.FormatUint(i, 10)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := range b.N {
		idx := i % len(keys)
		_ = cch.Set(b.Context(), keys[idx], value, time.Minute)
	}
}

func BenchmarkCache_Set_Parallel_Existing_1000(b *testing.B) {
	var idx atomic.Uint64

	cacheCapacity := uint64(1000)
	cch := prepareCache(b, cacheCapacity)
	value := []byte("updated-value")

	keys := make([]string, cacheCapacity)
	for i := range keys {
		keys[i] = "key-" + strconv.Itoa(i)
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			i := idx.Add(1) % cacheCapacity
			_ = cch.Set(b.Context(), keys[i], value, time.Minute)
		}
	})
}

func BenchmarkCache_Set_New_10000(b *testing.B) {
	cacheCapacity := uint64(10000)
	cch := prepareCache(b, cacheCapacity)
	value := []byte("new-value")

	keys := make([]string, b.N)
	for i := range b.N {
		keys[i] = "new-key-" + strconv.Itoa(i)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := range b.N {
		_ = cch.Set(b.Context(), keys[i], value, time.Minute)
	}
}

func BenchmarkCache_Set_Parallel_New_10000(b *testing.B) {
	var idx atomic.Uint64

	cacheCapacity := uint64(10000)
	cch := prepareCache(b, cacheCapacity)
	value := []byte("new-value")

	keys := make([]string, b.N)
	for i := range b.N {
		keys[i] = "new-key-" + strconv.Itoa(i)
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			i := idx.Add(1) - 1
			_ = cch.Set(b.Context(), keys[i], value, time.Minute)
		}
	})
}

func BenchmarkCache_Set_Existing_10000(b *testing.B) {
	cacheCapacity := uint64(10000)
	cch := prepareCache(b, cacheCapacity)
	value := []byte("updated-value")

	keys := make([]string, cacheCapacity)
	for i := range cacheCapacity {
		keys[i] = "key-" + strconv.FormatUint(i, 10)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := range b.N {
		idx := i % len(keys)
		_ = cch.Set(b.Context(), keys[idx], value, time.Minute)
	}
}

func BenchmarkCache_Set_Parallel_Existing_10000(b *testing.B) {
	var idx atomic.Uint64

	cacheCapacity := uint64(10000)
	cch := prepareCache(b, cacheCapacity)
	value := []byte("updated-value")

	keys := make([]string, cacheCapacity)
	for i := range keys {
		keys[i] = "key-" + strconv.Itoa(i)
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			i := idx.Add(1) % cacheCapacity
			_ = cch.Set(b.Context(), keys[i], value, time.Minute)
		}
	})
}
