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

package secrets

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/x/task"
)

func TestLeasedBindingResolveInitial(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		mode   ResolveMode
		setup  func(t *testing.T, calls *atomic.Int32) *leasedBinding[string]
		assert func(t *testing.T, entry *leasedBinding[string], calls *atomic.Int32, err error)
	}{
		"lazy schedules async initial resolve": {
			mode: ResolveLazy,
			setup: func(t *testing.T, calls *atomic.Int32) *leasedBinding[string] {
				t.Helper()

				bdg := newTestBinding(t, func(context.Context) (string, error) {
					calls.Add(1)

					return "resolved", nil
				})

				return newLeasedBinding(bdg)
			},
			assert: func(t *testing.T, entry *leasedBinding[string], calls *atomic.Int32, err error) {
				t.Helper()

				require.NoError(t, err)

				require.Eventually(t, func() bool {
					return calls.Load() == 1
				}, time.Second, 10*time.Millisecond)

				value, ok := entry.binding.peek()
				require.True(t, ok)
				require.Equal(t, "resolved", value)
			},
		},
		"eager resolves synchronously": {
			mode: ResolveEager,
			setup: func(t *testing.T, calls *atomic.Int32) *leasedBinding[string] {
				t.Helper()

				bdg := newTestBinding(t, func(context.Context) (string, error) {
					calls.Add(1)

					return "resolved", nil
				})

				return newLeasedBinding(bdg)
			},
			assert: func(t *testing.T, entry *leasedBinding[string], calls *atomic.Int32, err error) {
				t.Helper()

				require.NoError(t, err)
				require.EqualValues(t, 1, calls.Load())

				value, ok := entry.binding.peek()
				require.True(t, ok)
				require.Equal(t, "resolved", value)
			},
		},
		"eager returns resolve error": {
			mode: ResolveEager,
			setup: func(t *testing.T, calls *atomic.Int32) *leasedBinding[string] {
				t.Helper()

				bdg := newTestBinding(t, func(context.Context) (string, error) {
					calls.Add(1)

					return "", assert.AnError
				})

				return newLeasedBinding(bdg)
			},
			assert: func(t *testing.T, entry *leasedBinding[string], calls *atomic.Int32, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.EqualValues(t, 1, calls.Load())

				_, ok := entry.binding.peek()
				require.False(t, ok)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			var calls atomic.Int32

			executor, err := task.NewExecutor(1)
			require.NoError(t, err)
			t.Cleanup(executor.Stop)

			entry := tc.setup(t, &calls)

			err = entry.resolveInitial(context.Background(), executor, tc.mode)

			tc.assert(t, entry, &calls, err)
		})
	}
}

func TestLeasedBindingResolveInitialLazyDoesNotWaitForResolve(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32

	resolveStarted := make(chan struct{})
	releaseResolve := make(chan struct{})

	bdg := newTestBinding(t, func(context.Context) (string, error) {
		calls.Add(1)
		close(resolveStarted)

		<-releaseResolve

		return "resolved", nil
	})

	entry := newLeasedBinding(bdg)

	executor, err := task.NewExecutor(1)
	require.NoError(t, err)
	t.Cleanup(executor.Stop)

	err = entry.resolveInitial(context.Background(), executor, ResolveLazy)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		select {
		case <-resolveStarted:
			return true
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)

	_, ok := entry.binding.peek()
	require.False(t, ok)

	close(releaseResolve)

	require.Eventually(t, func() bool {
		value, ok := entry.binding.peek()

		return ok && value == "resolved"
	}, time.Second, 10*time.Millisecond)

	require.EqualValues(t, 1, calls.Load())
}

func TestLeasedBindingRun(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, logs *bytes.Buffer, calls *atomic.Int32) *leasedBinding[string]
		assert func(t *testing.T, entry *leasedBinding[string], logs *bytes.Buffer, calls *atomic.Int32)
	}{
		"resolves cached value": {
			setup: func(t *testing.T, _ *bytes.Buffer, calls *atomic.Int32) *leasedBinding[string] {
				t.Helper()

				bdg := newTestBinding(t, func(context.Context) (string, error) {
					calls.Add(1)

					return "resolved", nil
				})

				return newLeasedBinding(bdg)
			},
			assert: func(t *testing.T, entry *leasedBinding[string], _ *bytes.Buffer, calls *atomic.Int32) {
				t.Helper()

				require.EqualValues(t, 1, calls.Load())

				value, ok := entry.binding.peek()
				require.True(t, ok)
				require.Equal(t, "resolved", value)
			},
		},
		"logs resolve error": {
			setup: func(t *testing.T, logs *bytes.Buffer, calls *atomic.Int32) *leasedBinding[string] {
				t.Helper()

				bdg := newTestBinding(t, func(context.Context) (string, error) {
					calls.Add(1)

					return "", assert.AnError
				})
				bdg.logger = zerolog.New(logs)

				return newLeasedBinding(bdg)
			},
			assert: func(t *testing.T, entry *leasedBinding[string], logs *bytes.Buffer, calls *atomic.Int32) {
				t.Helper()

				require.EqualValues(t, 1, calls.Load())
				require.Contains(t, logs.String(), "Failed resolving secret binding")

				_, ok := entry.binding.peek()
				require.False(t, ok)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			var logs bytes.Buffer
			var calls atomic.Int32

			entry := tc.setup(t, &logs, &calls)

			entry.Run()

			tc.assert(t, entry, &logs, &calls)
		})
	}
}

func TestLeasedBindingUnschedule(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer

	bdg := newTestBinding[string](t, nil)
	bdg.logger = zerolog.New(&logs)

	entry := newLeasedBinding(bdg)

	require.True(t, entry.Schedule())

	entry.Unschedule(assert.AnError)

	require.True(t, entry.Schedule())
	require.Contains(t, logs.String(), "Failed scheduling initial secret binding resolve task")
}

func TestLeasedBindingStop(t *testing.T) {
	t.Parallel()

	bdg := newTestBinding[string](t, nil)
	bdg.subscribe(func(context.Context, string) error { return nil })

	entry := newLeasedBinding(bdg)

	require.True(t, entry.Schedule())
	require.True(t, entry.binding.Schedule())
	require.NotEmpty(t, entry.binding.callbacks)

	entry.stop()

	require.False(t, entry.Schedule())
	require.False(t, entry.binding.Schedule())
	require.Empty(t, entry.binding.callbacks)
}
