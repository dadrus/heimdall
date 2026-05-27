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
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBindingResolveOnce(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		initialValue string
		groupKey     resolveGroupKey
		setup        func(t *testing.T, calls *atomic.Int32) func(context.Context) (string, error)
		wantValue    string
		wantCalls    int32
		wantErr      error
	}{
		"cached resolve returns existing value": {
			initialValue: "cached",
			groupKey:     resolveGroupCached,
			setup: func(t *testing.T, calls *atomic.Int32) func(context.Context) (string, error) {
				t.Helper()

				return func(context.Context) (string, error) {
					calls.Add(1)

					return "resolved", nil
				}
			},
			wantValue: "cached",
			wantCalls: 0,
		},
		"cached resolve resolves missing value": {
			groupKey: resolveGroupCached,
			setup: func(t *testing.T, calls *atomic.Int32) func(context.Context) (string, error) {
				t.Helper()

				return func(context.Context) (string, error) {
					calls.Add(1)

					return "resolved", nil
				}
			},
			wantValue: "resolved",
			wantCalls: 1,
		},
		"forced resolve ignores existing value": {
			initialValue: "cached",
			groupKey:     resolveGroupForced,
			setup: func(t *testing.T, calls *atomic.Int32) func(context.Context) (string, error) {
				t.Helper()

				return func(context.Context) (string, error) {
					calls.Add(1)

					return "forced", nil
				}
			},
			wantValue: "forced",
			wantCalls: 1,
		},
		"returns resolve error": {
			groupKey: resolveGroupCached,
			setup: func(t *testing.T, calls *atomic.Int32) func(context.Context) (string, error) {
				t.Helper()

				return func(context.Context) (string, error) {
					calls.Add(1)

					return "", assert.AnError
				}
			},
			wantCalls: 1,
			wantErr:   assert.AnError,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			var calls atomic.Int32

			bdg := newTestBinding(t, tc.setup(t, &calls))
			if tc.initialValue != "" {
				bdg.publish(t.Context(), tc.initialValue)
			}

			got, err := bdg.resolveOnce(t.Context(), tc.groupKey)

			if tc.wantErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.wantErr)
				require.ErrorIs(t, bdg.getLastErr(), tc.wantErr)
				require.Empty(t, got)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.wantValue, got)

				cached, ok := bdg.peek()
				require.True(t, ok)
				require.Equal(t, tc.wantValue, cached)
				require.NoError(t, bdg.awaitReady(t.Context()))
				require.NoError(t, bdg.getLastErr())
			}

			require.Equal(t, tc.wantCalls, calls.Load())
		})
	}
}

func TestBindingResolveOnceDeduplicatesConcurrentCachedResolves(t *testing.T) {
	t.Parallel()

	const goroutines = 10

	var calls atomic.Int32

	release := make(chan struct{})

	var closeRelease sync.Once

	t.Cleanup(func() {
		closeRelease.Do(func() {
			close(release)
		})
	})

	bdg := newTestBinding(t, func(context.Context) (string, error) {
		calls.Add(1)

		<-release

		return "resolved", nil
	})

	type result struct {
		value string
		err   error
	}

	results := make(chan result, goroutines)

	for range goroutines {
		go func() {
			value, err := bdg.resolveOnce(t.Context(), resolveGroupCached)
			results <- result{
				value: value,
				err:   err,
			}
		}()
	}

	require.Eventually(t, func() bool {
		return calls.Load() == 1
	}, time.Second, 10*time.Millisecond)

	closeRelease.Do(func() {
		close(release)
	})

	for range goroutines {
		got := <-results

		require.NoError(t, got.err)
		require.Equal(t, "resolved", got.value)
	}

	value, ok := bdg.peek()
	require.True(t, ok)
	require.Equal(t, "resolved", value)
	require.NoError(t, bdg.awaitReady(t.Context()))
	require.NoError(t, bdg.getLastErr())
	require.EqualValues(t, 1, calls.Load())
}

func TestBindingResolveOnceHonorsContextWhileWaitingForRunningResolve(t *testing.T) {
	t.Parallel()

	resolveStarted := make(chan struct{})
	releaseResolve := make(chan struct{})

	var closeRelease sync.Once

	t.Cleanup(func() {
		closeRelease.Do(func() {
			close(releaseResolve)
		})
	})

	var (
		calls atomic.Int32
		once  sync.Once
	)

	bdg := newTestBinding(t, func(context.Context) (string, error) {
		calls.Add(1)

		once.Do(func() {
			close(resolveStarted)
		})

		<-releaseResolve

		return "resolved", nil
	})

	_, ok := bdg.peek()
	require.False(t, ok)

	type result struct {
		value string
		err   error
	}

	resolveDone := make(chan result, 1)

	go func() {
		value, err := bdg.resolveOnce(t.Context(), resolveGroupCached)
		resolveDone <- result{
			value: value,
			err:   err,
		}
	}()

	require.Eventually(t, func() bool {
		select {
		case <-resolveStarted:
			return true
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()

	got, err := bdg.resolveOnce(ctx, resolveGroupCached)

	closeRelease.Do(func() {
		close(releaseResolve)
	})

	require.Error(t, err)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Empty(t, got)
	require.EqualValues(t, 1, calls.Load())

	select {
	case first := <-resolveDone:
		require.NoError(t, first.err)
		require.Equal(t, "resolved", first.value)
	case <-time.After(time.Second):
		require.Fail(t, "background resolve did not finish")
	}

	value, ok := bdg.peek()
	require.True(t, ok)
	require.Equal(t, "resolved", value)
	require.NoError(t, bdg.awaitReady(t.Context()))
	require.NoError(t, bdg.getLastErr())
}

func TestBindingRefresh(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, calls *guardedCalls) *binding[string]
		assert func(t *testing.T, bdg *binding[string], calls *guardedCalls, err error)
	}{
		"forces resolve and publishes value": {
			setup: func(t *testing.T, calls *guardedCalls) *binding[string] {
				t.Helper()

				bdg := newTestBinding(t, func(context.Context) (string, error) {
					calls.Add("resolve")

					return "new-value", nil
				})
				bdg.value.Store("old-value")
				bdg.subscribe(func(_ context.Context, value string) error {
					calls.Add("callback:" + value)

					return nil
				})

				return bdg
			},
			assert: func(t *testing.T, bdg *binding[string], calls *guardedCalls, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, []string{
					"callback:old-value",
					"resolve",
					"callback:new-value",
				}, calls.All())

				value, ok := bdg.peek()
				require.True(t, ok)
				require.Equal(t, "new-value", value)
			},
		},
		"returns resolve error and does not publish": {
			setup: func(t *testing.T, calls *guardedCalls) *binding[string] {
				t.Helper()

				bdg := newTestBinding(t, func(context.Context) (string, error) {
					calls.Add("resolve")

					return "", assert.AnError
				})
				bdg.subscribe(func(_ context.Context, value string) error {
					calls.Add("callback:" + value)

					return nil
				})

				return bdg
			},
			assert: func(t *testing.T, bdg *binding[string], calls *guardedCalls, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.Equal(t, []string{"resolve"}, calls.All())

				_, ok := bdg.peek()
				require.False(t, ok)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			var calls guardedCalls

			bdg := tc.setup(t, &calls)

			err := bdg.refresh(context.Background())

			tc.assert(t, bdg, &calls, err)
		})
	}
}

func TestBindingSubscribe(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, calls *guardedCalls) (*binding[string], func())
		assert func(t *testing.T, bdg *binding[string], calls *guardedCalls, cleanup func())
	}{
		"registers callback and immediately notifies with current value": {
			setup: func(t *testing.T, calls *guardedCalls) (*binding[string], func()) {
				t.Helper()

				bdg := newTestBinding[string](t, nil)
				bdg.value.Store("current")

				cleanup := bdg.subscribe(func(_ context.Context, value string) error {
					calls.Add("callback:" + value)

					return nil
				})

				return bdg, cleanup
			},
			assert: func(t *testing.T, bdg *binding[string], calls *guardedCalls, cleanup func()) {
				t.Helper()

				require.Equal(t, []string{"callback:current"}, calls.All())
				require.Len(t, bdg.callbacks, 1)

				cleanup()
				require.Empty(t, bdg.callbacks)
			},
		},
		"registers callback without immediate notification if value is unavailable": {
			setup: func(t *testing.T, calls *guardedCalls) (*binding[string], func()) {
				t.Helper()

				bdg := newTestBinding[string](t, nil)

				cleanup := bdg.subscribe(func(_ context.Context, value string) error {
					calls.Add("callback:" + value)

					return nil
				})

				return bdg, cleanup
			},
			assert: func(t *testing.T, bdg *binding[string], calls *guardedCalls, cleanup func()) {
				t.Helper()

				require.Empty(t, calls.All())
				require.Len(t, bdg.callbacks, 1)

				bdg.publish(t.Context(), "published")
				require.Equal(t, []string{"callback:published"}, calls.All())

				cleanup()
				require.Empty(t, bdg.callbacks)
			},
		},
		"nil callback is ignored": {
			setup: func(t *testing.T, _ *guardedCalls) (*binding[string], func()) {
				t.Helper()

				bdg := newTestBinding[string](t, nil)

				return bdg, bdg.subscribe(nil)
			},
			assert: func(t *testing.T, bdg *binding[string], calls *guardedCalls, cleanup func()) {
				t.Helper()

				require.Empty(t, calls.All())
				require.Empty(t, bdg.callbacks)

				require.NotPanics(t, cleanup)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			var calls guardedCalls

			bdg, cleanup := tc.setup(t, &calls)

			tc.assert(t, bdg, &calls, cleanup)
		})
	}
}

func TestBindingPublish(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, logs *bytes.Buffer, calls *guardedCalls) *binding[string]
		assert func(t *testing.T, bdg *binding[string], logs *bytes.Buffer, calls *guardedCalls)
	}{
		"stores value and notifies subscribers": {
			setup: func(t *testing.T, _ *bytes.Buffer, calls *guardedCalls) *binding[string] {
				t.Helper()

				bdg := newTestBinding[string](t, nil)
				bdg.subscribe(func(_ context.Context, value string) error {
					calls.Add("a:" + value)

					return nil
				})
				bdg.subscribe(func(_ context.Context, value string) error {
					calls.Add("b:" + value)

					return nil
				})

				return bdg
			},
			assert: func(t *testing.T, bdg *binding[string], _ *bytes.Buffer, calls *guardedCalls) {
				t.Helper()

				require.NoError(t, bdg.awaitReady(t.Context()))

				value, ok := bdg.peek()
				require.True(t, ok)
				require.Equal(t, "published", value)

				require.ElementsMatch(t, []string{
					"a:published",
					"b:published",
				}, calls.All())
			},
		},
		"logs callback errors": {
			setup: func(t *testing.T, _ *bytes.Buffer, _ *guardedCalls) *binding[string] {
				t.Helper()

				bdg := newTestBinding[string](t, nil)
				bdg.subscribe(func(context.Context, string) error {
					return assert.AnError
				})

				return bdg
			},
			assert: func(t *testing.T, _ *binding[string], logs *bytes.Buffer, _ *guardedCalls) {
				t.Helper()

				require.Contains(t, logs.String(), "Secret binding update callback failed")
				require.Contains(t, logs.String(), "_source")
				require.Contains(t, logs.String(), "source")
				require.Contains(t, logs.String(), "_selector")
				require.Contains(t, logs.String(), "selector")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			var (
				logs  bytes.Buffer
				calls guardedCalls
			)

			bdg := tc.setup(t, &logs, &calls)
			bdg.logger = zerolog.New(&logs)

			bdg.publish(t.Context(), "published")

			tc.assert(t, bdg, &logs, &calls)
		})
	}
}

func TestBindingRun(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, logs *bytes.Buffer, calls *guardedCalls) *binding[string]
		assert func(t *testing.T, bdg *binding[string], logs *bytes.Buffer, calls *guardedCalls)
	}{
		"refreshes binding": {
			setup: func(t *testing.T, _ *bytes.Buffer, calls *guardedCalls) *binding[string] {
				t.Helper()

				return newTestBinding(t, func(context.Context) (string, error) {
					calls.Add("resolve")

					return "refreshed", nil
				})
			},
			assert: func(t *testing.T, bdg *binding[string], _ *bytes.Buffer, calls *guardedCalls) {
				t.Helper()

				require.NoError(t, bdg.awaitReady(t.Context()))

				require.Equal(t, []string{"resolve"}, calls.All())

				value, ok := bdg.peek()
				require.True(t, ok)
				require.Equal(t, "refreshed", value)
			},
		},
		"logs refresh error": {
			setup: func(t *testing.T, _ *bytes.Buffer, calls *guardedCalls) *binding[string] {
				t.Helper()

				return newTestBinding(t, func(context.Context) (string, error) {
					calls.Add("resolve")

					return "", assert.AnError
				})
			},
			assert: func(t *testing.T, _ *binding[string], logs *bytes.Buffer, calls *guardedCalls) {
				t.Helper()

				require.Equal(t, []string{"resolve"}, calls.All())
				require.Contains(t, logs.String(), "Failed refreshing secret binding")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			var (
				logs  bytes.Buffer
				calls guardedCalls
			)

			bdg := tc.setup(t, &logs, &calls)
			bdg.logger = zerolog.New(&logs)

			bdg.Run()

			tc.assert(t, bdg, &logs, &calls)
		})
	}
}

func TestBindingUnschedule(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer

	bdg := newTestBinding[string](t, nil)
	bdg.logger = zerolog.New(&logs)

	require.True(t, bdg.Schedule())

	bdg.Unschedule(assert.AnError)

	require.True(t, bdg.Schedule())
	require.Contains(t, logs.String(), "Failed scheduling secret binding refresh task")
}

func TestBindingStop(t *testing.T) {
	t.Parallel()

	bdg := newTestBinding[string](t, nil)
	bdg.subscribe(func(context.Context, string) error { return nil })

	require.NotEmpty(t, bdg.callbacks)

	bdg.stop()

	require.Empty(t, bdg.callbacks)
	require.False(t, bdg.Schedule())
}

func TestBindingAwaitReady(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T) (*binding[string], context.Context)
		assert func(t *testing.T, err error)
	}{
		"returns nil after publish": {
			setup: func(t *testing.T) (*binding[string], context.Context) {
				t.Helper()

				bdg := newTestBinding[string](t, nil)
				bdg.publish(t.Context(), "ready")

				return bdg, t.Context()
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"returns context error if no value and no last error": {
			setup: func(t *testing.T) (*binding[string], context.Context) {
				t.Helper()

				ctx, cancel := context.WithCancel(t.Context())
				cancel()

				return newTestBinding[string](t, nil), ctx
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, context.Canceled)
			},
		},
		"returns last error if no value and last error exists": {
			setup: func(t *testing.T) (*binding[string], context.Context) {
				t.Helper()

				bdg := newTestBinding(t, func(context.Context) (string, error) {
					return "", assert.AnError
				})

				_, err := bdg.resolveOnce(t.Context(), resolveGroupCached)
				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)

				ctx, cancel := context.WithCancel(t.Context())
				cancel()

				return bdg, ctx
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			bdg, ctx := tc.setup(t)

			tc.assert(t, bdg.awaitReady(ctx))
		})
	}
}

func TestBindingLastErr(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T) *binding[string]
		assert func(t *testing.T, bdg *binding[string])
	}{
		"resolve error stores last error": {
			setup: func(t *testing.T) *binding[string] {
				t.Helper()

				bdg := newTestBinding(t, func(context.Context) (string, error) {
					return "", assert.AnError
				})

				_, err := bdg.resolveOnce(t.Context(), resolveGroupCached)
				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)

				return bdg
			},
			assert: func(t *testing.T, bdg *binding[string]) {
				t.Helper()

				require.ErrorIs(t, bdg.getLastErr(), assert.AnError)
			},
		},
		"successful resolve clears last error": {
			setup: func(t *testing.T) *binding[string] {
				t.Helper()

				bdg := newTestBinding(t, func(context.Context) (string, error) {
					return "resolved", nil
				})
				bdg.setLastErr(assert.AnError)

				_, err := bdg.resolveOnce(t.Context(), resolveGroupForced)
				require.NoError(t, err)

				return bdg
			},
			assert: func(t *testing.T, bdg *binding[string]) {
				t.Helper()

				require.NoError(t, bdg.getLastErr())
			},
		},
		"publish clears last error": {
			setup: func(t *testing.T) *binding[string] {
				t.Helper()

				bdg := newTestBinding[string](t, nil)
				bdg.setLastErr(assert.AnError)
				bdg.publish(t.Context(), "published")

				return bdg
			},
			assert: func(t *testing.T, bdg *binding[string]) {
				t.Helper()

				require.NoError(t, bdg.getLastErr())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			bdg := tc.setup(t)

			tc.assert(t, bdg)
		})
	}
}

func newTestBinding[T any](
	t *testing.T,
	resolve func(context.Context) (T, error),
) *binding[T] {
	t.Helper()

	if resolve == nil {
		resolve = func(context.Context) (T, error) {
			var zero T

			return zero, errors.New("unexpected resolve call")
		}
	}

	return newBinding(
		bindingKey{
			kind:      bindingKindSecret,
			source:    "source",
			selector:  "selector",
			namespace: "namespace",
			scope:     referenceScopeInternal,
		},
		zerolog.Nop(),
		resolve,
	)
}

type guardedCalls struct {
	mu    sync.Mutex
	calls []string
}

func (c *guardedCalls) Add(call string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.calls = append(c.calls, call)
}

func (c *guardedCalls) All() []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	return append([]string{}, c.calls...)
}
