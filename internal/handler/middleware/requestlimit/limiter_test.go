// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
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

package requestlimit

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLimiterTryAcquire(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		limit int64
		setup func(t *testing.T, limiter *Limiter)
		want  bool
	}{
		"acquires capacity": {
			limit: 1,
			want:  true,
		},
		"rejects if capacity is exhausted": {
			limit: 1,
			setup: func(t *testing.T, limiter *Limiter) {
				t.Helper()

				require.True(t, limiter.TryAcquire())
			},
			want: false,
		},
		"disabled limit always acquires": {
			limit: 0,
			setup: func(t *testing.T, limiter *Limiter) {
				t.Helper()

				for range 10 {
					require.True(t, limiter.TryAcquire())
				}
			},
			want: true,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			limiter := New(tc.limit)

			if tc.setup != nil {
				tc.setup(t, limiter)
			}

			// WHEN
			acquired := limiter.TryAcquire()

			// THEN
			assert.Equal(t, tc.want, acquired)
		})
	}

	t.Run("does not exceed capacity under concurrency", func(t *testing.T) {
		// GIVEN
		const (
			limit      = 5
			contenders = 100
		)

		limiter := New(limit)

		start := make(chan struct{})
		var acquired atomic.Int32
		var wg sync.WaitGroup

		wg.Add(contenders)

		// WHEN
		for range contenders {
			go func() {
				defer wg.Done()

				<-start

				if limiter.TryAcquire() {
					acquired.Add(1)
				}
			}()
		}

		close(start)
		wg.Wait()

		// THEN
		assert.Equal(t, int32(limit), acquired.Load())
	})
}

func TestLimiterRelease(t *testing.T) {
	t.Parallel()

	t.Run("releases acquired capacity", func(t *testing.T) {
		// GIVEN
		limiter := New(1)

		require.True(t, limiter.TryAcquire())
		require.False(t, limiter.TryAcquire())

		// WHEN
		limiter.Release()

		// THEN
		assert.True(t, limiter.TryAcquire())
	})

	t.Run("does nothing if limit is disabled", func(t *testing.T) {
		// GIVEN
		limiter := New(0)

		// WHEN
		limiter.Release()

		// THEN
		assert.True(t, limiter.TryAcquire())
	})
}
