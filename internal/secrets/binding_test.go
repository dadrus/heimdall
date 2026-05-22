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

func TestBindingGet(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup      func(t *testing.T, calls *atomic.Int32) *binding[string]
		wantValue  string
		wantOK     bool
		wantCalls  int32
		wantCached bool
	}{
		"returns cached value without resolving": {
			setup: func(t *testing.T, calls *atomic.Int32) *binding[string] {
				t.Helper()

				bdg := newTestBinding(t, func(context.Context) (string, error) {
					calls.Add(1)

					return "resolved", nil
				})
				bdg.value.Store("cached")

				return bdg
			},
			wantValue:  "cached",
			wantOK:     true,
			wantCalls:  0,
			wantCached: true,
		},
		"resolves missing value and publishes it": {
			setup: func(t *testing.T, calls *atomic.Int32) *binding[string] {
				t.Helper()

				return newTestBinding(t, func(context.Context) (string, error) {
					calls.Add(1)

					return "resolved", nil
				})
			},
			wantValue:  "resolved",
			wantOK:     true,
			wantCalls:  1,
			wantCached: true,
		},
		"returns false if resolve fails": {
			setup: func(t *testing.T, calls *atomic.Int32) *binding[string] {
				t.Helper()

				return newTestBinding(t, func(context.Context) (string, error) {
					calls.Add(1)

					return "", assert.AnError
				})
			},
			wantOK:    false,
			wantCalls: 1,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			var calls atomic.Int32

			bdg := tc.setup(t, &calls)

			got, ok := bdg.get(context.Background())

			require.Equal(t, tc.wantOK, ok)
			require.Equal(t, tc.wantValue, got)
			require.Equal(t, tc.wantCalls, calls.Load())

			if tc.wantCached {
				cached, ok := bdg.peek()
				require.True(t, ok)
				require.Equal(t, tc.wantValue, cached)
			}
		})
	}
}

func TestBindingGetReturnsFalseIfContextAwareResolveFails(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	bdg := newTestBinding(t, func(ctx context.Context) (string, error) {
		return "", ctx.Err()
	})

	got, ok := bdg.get(ctx)

	require.False(t, ok)
	require.Empty(t, got)
}

func TestBindingGetHonorsContextWhileWaitingForRunningResolve(t *testing.T) {
	t.Parallel()

	resolveStarted := make(chan struct{})
	releaseResolve := make(chan struct{})

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

	resolveDone := make(chan struct{})

	go func() {
		_, _ = bdg.resolveOnce(context.Background(), resolveGroupCached)

		close(resolveDone)
	}()

	require.Eventually(t, func() bool {
		select {
		case <-resolveStarted:
			return true
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	got, ok := bdg.get(ctx)

	require.False(t, ok)
	require.Empty(t, got)
	require.EqualValues(t, 1, calls.Load())

	close(releaseResolve)

	require.Eventually(t, func() bool {
		select {
		case <-resolveDone:
			return true
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)

	value, ok := bdg.peek()
	require.True(t, ok)
	require.Equal(t, "resolved", value)
}

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
				bdg.value.Store(tc.initialValue)
			}

			got, err := bdg.resolveOnce(context.Background(), tc.groupKey)

			if tc.wantErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.wantErr)
				require.Empty(t, got)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.wantValue, got)

				cached, ok := bdg.peek()
				require.True(t, ok)
				require.Equal(t, tc.wantValue, cached)
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

	bdg := newTestBinding(t, func(context.Context) (string, error) {
		calls.Add(1)
		<-release

		return "resolved", nil
	})

	var wg sync.WaitGroup
	results := make(chan string, goroutines)

	for range goroutines {
		wg.Go(func() {
			value, err := bdg.resolveOnce(context.Background(), resolveGroupCached)
			require.NoError(t, err)

			results <- value
		})
	}

	require.Eventually(t, func() bool {
		return calls.Load() == 1
	}, time.Second, 10*time.Millisecond)

	close(release)

	wg.Wait()
	close(results)

	for value := range results {
		require.Equal(t, "resolved", value)
	}

	require.EqualValues(t, 1, calls.Load())
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

				bdg.publish("published")
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

			var logs bytes.Buffer
			var calls guardedCalls

			bdg := tc.setup(t, &logs, &calls)
			bdg.logger = zerolog.New(&logs)

			bdg.publish("published")

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

			var logs bytes.Buffer
			var calls guardedCalls

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
