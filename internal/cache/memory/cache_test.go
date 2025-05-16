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
	"bytes"
	"context"
	"fmt"
	"strconv"
	"sync"
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

// waitTimeout waits for the waitgroup for the specified max timeout.
// Returns true if waiting timed out.
func waitTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()
	select {
	case <-c:
		return false // completed normally
	case <-time.After(timeout):
		return true // timed out
	}
}

func TestConcurrentAccess(t *testing.T) {
	t.Parallel()

	// Create cache
	cch, err := NewCache(nil, map[string]any{})
	require.NoError(t, err)

	err = cch.Start(t.Context())
	require.NoError(t, err)

	defer cch.Stop(t.Context())

	// Number of goroutines and operations per goroutine
	const numGoroutines = 20
	const numOperations = 200

	// WaitGroup to synchronize the start of goroutines
	var startWg sync.WaitGroup
	startWg.Add(1) // Only one Add, which will be Done by the main goroutine

	// WaitGroup to wait for all goroutines to complete
	var doneWg sync.WaitGroup
	doneWg.Add(numGoroutines)

	// Track errors
	errorsChan := make(chan error, numGoroutines*numOperations)

	// Create a context with timeout for detecting deadlocks
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	// Launch goroutines
	for i := 0; i < numGoroutines; i++ {
		go func(routineID int) {
			defer doneWg.Done()

			// Wait for the signal to start
			startWg.Wait()

			// Perform cache operations
			for j := 0; j < numOperations; j++ {
				// Check if we've timed out
				select {
				case <-ctx.Done():
					errorsChan <- fmt.Errorf("goroutine %d timed out after timeout", routineID)
					return
				default:
					// Continue with operation
				}

				key := fmt.Sprintf("key-%d-%d", routineID, j)
				value := []byte(fmt.Sprintf("value-%d-%d", routineID, j))

				// Set the value
				err := cch.Set(ctx, key, value, 10*time.Second)
				if err != nil {
					errorsChan <- fmt.Errorf("error in Set: goroutine %d, operation %d: %v", routineID, j, err)
					continue
				}

				// Get the value we just set to verify it
				retrievedValue, err := cch.Get(ctx, key)
				if err != nil {
					errorsChan <- fmt.Errorf("error in Get: goroutine %d, operation %d: %v", routineID, j, err)
					continue
				}

				// Verify the value matches what we set
				if !bytes.Equal(value, retrievedValue) {
					errorsChan <- fmt.Errorf("value mismatch: goroutine %d, operation %d", routineID, j)
				}
			}
		}(i)
	}

	// Start timer
	start := time.Now()

	// Signal all goroutines to start
	startWg.Done()

	// Wait for all goroutines with timeout
	if timedOut := waitTimeout(&doneWg, 2*time.Second); timedOut {
		t.Fatalf("Test timed out after 2 seconds - likely deadlock detected")
		return
	}

	// Check execution time
	execTime := time.Since(start)
	assert.LessOrEqual(t, execTime, 2*time.Second, "Concurrent operations took too long: %v", execTime)

	// Check errors
	close(errorsChan)
	var errors []error
	for err := range errorsChan {
		errors = append(errors, err)
	}
	assert.Empty(t, errors, "Encountered errors during concurrent operations")
}

func TestConcurrentAccessSameItem(t *testing.T) {
	t.Parallel()

	// Create cache
	cch, err := NewCache(nil, map[string]any{})
	require.NoError(t, err)

	err = cch.Start(t.Context())
	require.NoError(t, err)

	defer cch.Stop(t.Context())

	// Set a shared counter to 0
	sharedKey := "shared-counter"
	err = cch.Set(t.Context(), sharedKey, []byte("0"), 10*time.Second)
	require.NoError(t, err)

	// Number of goroutines and operations per goroutine
	const numGoroutines = 20
	const numOperations = 200

	// WaitGroup to synchronize the start of goroutines
	var startWg sync.WaitGroup
	startWg.Add(1) // Only one Add, which will be Done by the main goroutine

	// WaitGroup to wait for all goroutines to complete
	var doneWg sync.WaitGroup
	doneWg.Add(numGoroutines)

	// Track errors
	errorsChan := make(chan error, numGoroutines*numOperations)

	// Create a context with timeout for detecting deadlocks
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	// Launch goroutines
	for i := 0; i < numGoroutines; i++ {
		go func(routineID int) {
			defer doneWg.Done()

			// Wait for the signal to start
			startWg.Wait()

			// Perform cache operations on the shared counter
			for j := 0; j < numOperations; j++ {
				// Check if we've timed out
				select {
				case <-ctx.Done():
					errorsChan <- fmt.Errorf("goroutine %d timed out after timeout", routineID)
					return
				default:
					// Continue with operation
				}

				// Get current counter value
				value, err := cch.Get(ctx, sharedKey)
				if err != nil {
					errorsChan <- fmt.Errorf("error reading in goroutine %d, operation %d: %v", routineID, j, err)
					continue
				}

				// Parse the value as integer
				count, err := strconv.Atoi(string(value))
				if err != nil {
					errorsChan <- fmt.Errorf("error parsing value '%s' in goroutine %d, operation %d: %v", string(value), routineID, j, err)
					continue
				}

				// Increment the counter
				count++

				// Set the new value
				err = cch.Set(ctx, sharedKey, []byte(strconv.Itoa(count)), 10*time.Second)
				if err != nil {
					errorsChan <- fmt.Errorf("error writing in goroutine %d, operation %d: %v", routineID, j, err)
					continue
				}
			}
		}(i)
	}

	// Start timer
	start := time.Now()

	// Signal all goroutines to start
	startWg.Done()

	// Wait for all goroutines with timeout
	if timedOut := waitTimeout(&doneWg, 2*time.Second); timedOut {
		t.Fatalf("Test timed out after 2 seconds - likely deadlock detected")
		return
	}

	// Check execution time
	execTime := time.Since(start)
	assert.LessOrEqual(t, execTime, 2*time.Second, "Concurrent operations took too long: %v", execTime)

	// Check errors
	close(errorsChan)
	var errors []error
	for err := range errorsChan {
		errors = append(errors, err)
	}
	assert.Empty(t, errors, "Encountered errors during concurrent operations")

	// Verify the final counter value
	//finalValue, err := cch.Get(t.Context(), sharedKey)
	//require.NoError(t, err)

	//finalCount, err := strconv.Atoi(string(finalValue))
	//require.NoError(t, err)

	// Note: If there are race conditions, the final count will be less than expected
	// Disabled.. get and set are not atomic, so this will not always be true
	//expectedCount := numGoroutines * numOperations
	//assert.Equal(t, expectedCount, finalCount, "Final counter value doesn't match expected operations count")
}
