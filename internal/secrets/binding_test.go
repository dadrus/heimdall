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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/secrets/metrics/mocks"
	secrettypes "github.com/dadrus/heimdall/internal/secrets/types"
)

func TestBindingResolveOnce(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		initialValue Secret
		groupKey     resolveGroupKey
		setup        func(t *testing.T, usage *mocks.SecretUsageMock, calls *atomic.Int32) func(context.Context) (Secret, error)
		wantValue    Secret
		wantCalls    int32
		wantErr      error
	}{
		"cached resolve returns existing value": {
			initialValue: secrettypes.NewStringSecret("cached", "cached"),
			groupKey:     resolveGroupCached,
			setup: func(t *testing.T, usage *mocks.SecretUsageMock, calls *atomic.Int32) func(context.Context) (Secret, error) {
				t.Helper()

				usage.EXPECT().
					Track(secrettypes.NewStringSecret("cached", "cached")).
					Once()

				return func(context.Context) (Secret, error) {
					calls.Add(1)

					return secrettypes.NewStringSecret("resolved", "resolved"), nil
				}
			},
			wantValue: secrettypes.NewStringSecret("cached", "cached"),
			wantCalls: 0,
		},
		"cached resolve resolves missing value": {
			groupKey: resolveGroupCached,
			setup: func(t *testing.T, usage *mocks.SecretUsageMock, calls *atomic.Int32) func(context.Context) (Secret, error) {
				t.Helper()

				usage.EXPECT().
					Track(secrettypes.NewStringSecret("resolved", "resolved")).
					Once()

				return func(context.Context) (Secret, error) {
					calls.Add(1)

					return secrettypes.NewStringSecret("resolved", "resolved"), nil
				}
			},
			wantValue: secrettypes.NewStringSecret("resolved", "resolved"),
			wantCalls: 1,
		},
		"forced resolve ignores existing value": {
			initialValue: secrettypes.NewStringSecret("cached", "cached"),
			groupKey:     resolveGroupForced,
			setup: func(t *testing.T, usage *mocks.SecretUsageMock, calls *atomic.Int32) func(context.Context) (Secret, error) {
				t.Helper()

				usage.EXPECT().
					Track(secrettypes.NewStringSecret("cached", "cached")).
					Once()
				usage.EXPECT().
					Track(secrettypes.NewStringSecret("forced", "forced")).
					Once()
				usage.EXPECT().
					Untrack(secrettypes.NewStringSecret("cached", "cached")).
					Once()

				return func(context.Context) (Secret, error) {
					calls.Add(1)

					return secrettypes.NewStringSecret("forced", "forced"), nil
				}
			},
			wantValue: secrettypes.NewStringSecret("forced", "forced"),
			wantCalls: 1,
		},
		"returns resolve error": {
			groupKey: resolveGroupCached,
			setup: func(t *testing.T, _ *mocks.SecretUsageMock, calls *atomic.Int32) func(context.Context) (Secret, error) {
				t.Helper()

				return func(context.Context) (Secret, error) {
					calls.Add(1)

					return nil, assert.AnError
				}
			},
			wantCalls: 1,
			wantErr:   assert.AnError,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			var calls atomic.Int32

			usage := mocks.NewSecretUsageMock(t)
			bdg := newBinding(
				bindingKey{
					kind:      bindingKindSecret,
					source:    "source",
					selector:  "selector",
					namespace: "namespace",
					scope:     referenceScopeInternal,
				},
				zerolog.Nop(),
				usage,
				tc.setup(t, usage, &calls),
			)

			if tc.initialValue != nil {
				bdg.publish(t.Context(), tc.initialValue)
			}

			got, err := bdg.resolveOnce(t.Context(), tc.groupKey)

			if tc.wantErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.wantErr)
				require.ErrorIs(t, bdg.getLastErr(), tc.wantErr)
				require.Nil(t, got)
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

	usage := mocks.NewSecretUsageMock(t)
	usage.EXPECT().
		Track(secrettypes.NewStringSecret("resolved", "resolved")).
		Once()

	bdg := newBinding(
		bindingKey{
			kind:      bindingKindSecret,
			source:    "source",
			selector:  "selector",
			namespace: "namespace",
			scope:     referenceScopeInternal,
		},
		zerolog.Nop(),
		usage,
		func(context.Context) (Secret, error) {
			calls.Add(1)

			<-release

			return secrettypes.NewStringSecret("resolved", "resolved"), nil
		},
	)

	type result struct {
		value Secret
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
		require.Equal(t, secrettypes.NewStringSecret("resolved", "resolved"), got.value)
	}

	value, ok := bdg.peek()
	require.True(t, ok)
	require.Equal(t, secrettypes.NewStringSecret("resolved", "resolved"), value)
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

	usage := mocks.NewSecretUsageMock(t)
	usage.EXPECT().
		Track(secrettypes.NewStringSecret("resolved", "resolved")).
		Once()

	bdg := newBinding(
		bindingKey{
			kind:      bindingKindSecret,
			source:    "source",
			selector:  "selector",
			namespace: "namespace",
			scope:     referenceScopeInternal,
		},
		zerolog.Nop(),
		usage,
		func(context.Context) (Secret, error) {
			calls.Add(1)

			once.Do(func() {
				close(resolveStarted)
			})

			<-releaseResolve

			return secrettypes.NewStringSecret("resolved", "resolved"), nil
		},
	)

	_, ok := bdg.peek()
	require.False(t, ok)

	type result struct {
		value Secret
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
	require.Nil(t, got)
	require.EqualValues(t, 1, calls.Load())

	select {
	case first := <-resolveDone:
		require.NoError(t, first.err)
		require.Equal(t, secrettypes.NewStringSecret("resolved", "resolved"), first.value)
	case <-time.After(time.Second):
		require.Fail(t, "background resolve did not finish")
	}

	value, ok := bdg.peek()
	require.True(t, ok)
	require.Equal(t, secrettypes.NewStringSecret("resolved", "resolved"), value)
	require.NoError(t, bdg.awaitReady(t.Context()))
	require.NoError(t, bdg.getLastErr())
}

func TestBindingRefresh(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, usage *mocks.SecretUsageMock, calls *guardedCalls) *binding[Secret]
		assert func(t *testing.T, bdg *binding[Secret], calls *guardedCalls, err error)
	}{
		"forces resolve and publishes value": {
			setup: func(t *testing.T, usage *mocks.SecretUsageMock, calls *guardedCalls) *binding[Secret] {
				t.Helper()

				usage.EXPECT().
					Track(secrettypes.NewStringSecret("old-value", "old-value")).
					Once()
				usage.EXPECT().
					Track(secrettypes.NewStringSecret("new-value", "new-value")).
					Once()
				usage.EXPECT().
					Untrack(secrettypes.NewStringSecret("old-value", "old-value")).
					Once()

				bdg := newBinding(
					bindingKey{
						kind:      bindingKindSecret,
						source:    "source",
						selector:  "selector",
						namespace: "namespace",
						scope:     referenceScopeInternal,
					},
					zerolog.Nop(),
					usage,
					func(context.Context) (Secret, error) {
						calls.Add("resolve")

						return secrettypes.NewStringSecret("new-value", "new-value"), nil
					},
				)

				bdg.publish(t.Context(), secrettypes.NewStringSecret("old-value", "old-value"))
				bdg.subscribe(func(_ context.Context, value Secret) error {
					calls.Add("callback:" + value.Selector())

					return nil
				})

				return bdg
			},
			assert: func(t *testing.T, bdg *binding[Secret], calls *guardedCalls, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, []string{
					"callback:old-value",
					"resolve",
					"callback:new-value",
				}, calls.All())

				value, ok := bdg.peek()
				require.True(t, ok)
				require.Equal(t, secrettypes.NewStringSecret("new-value", "new-value"), value)
			},
		},
		"returns resolve error and does not publish": {
			setup: func(t *testing.T, usage *mocks.SecretUsageMock, calls *guardedCalls) *binding[Secret] {
				t.Helper()

				bdg := newBinding(
					bindingKey{
						kind:      bindingKindSecret,
						source:    "source",
						selector:  "selector",
						namespace: "namespace",
						scope:     referenceScopeInternal,
					},
					zerolog.Nop(),
					usage,
					func(context.Context) (Secret, error) {
						calls.Add("resolve")

						return nil, assert.AnError
					},
				)
				bdg.subscribe(func(_ context.Context, value Secret) error {
					calls.Add("callback:" + value.Selector())

					return nil
				})

				return bdg
			},
			assert: func(t *testing.T, bdg *binding[Secret], calls *guardedCalls, err error) {
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

			usage := mocks.NewSecretUsageMock(t)
			bdg := tc.setup(t, usage, &calls)

			err := bdg.refresh(context.Background())

			tc.assert(t, bdg, &calls, err)
		})
	}
}

func TestBindingSubscribe(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, usage *mocks.SecretUsageMock, calls *guardedCalls) (*binding[Secret], func())
		assert func(t *testing.T, bdg *binding[Secret], calls *guardedCalls, cleanup func())
	}{
		"registers callback and immediately notifies with current value": {
			setup: func(t *testing.T, usage *mocks.SecretUsageMock, calls *guardedCalls) (*binding[Secret], func()) {
				t.Helper()

				usage.EXPECT().
					Track(secrettypes.NewStringSecret("current", "current")).
					Once()

				bdg := newBinding[Secret](
					bindingKey{
						kind:      bindingKindSecret,
						source:    "source",
						selector:  "selector",
						namespace: "namespace",
						scope:     referenceScopeInternal,
					},
					zerolog.Nop(),
					usage,
					nil,
				)
				bdg.publish(t.Context(), secrettypes.NewStringSecret("current", "current"))

				cleanup := bdg.subscribe(func(_ context.Context, value Secret) error {
					calls.Add("callback:" + value.Selector())

					return nil
				})

				return bdg, cleanup
			},
			assert: func(t *testing.T, bdg *binding[Secret], calls *guardedCalls, cleanup func()) {
				t.Helper()

				require.Equal(t, []string{"callback:current"}, calls.All())
				require.Len(t, bdg.callbacks, 1)

				cleanup()
				require.Empty(t, bdg.callbacks)
			},
		},
		"registers callback without immediate notification if value is unavailable": {
			setup: func(t *testing.T, usage *mocks.SecretUsageMock, calls *guardedCalls) (*binding[Secret], func()) {
				t.Helper()

				usage.EXPECT().
					Track(secrettypes.NewStringSecret("published", "published")).
					Once()

				bdg := newBinding[Secret](
					bindingKey{
						kind:      bindingKindSecret,
						source:    "source",
						selector:  "selector",
						namespace: "namespace",
						scope:     referenceScopeInternal,
					},
					zerolog.Nop(),
					usage,
					nil,
				)

				cleanup := bdg.subscribe(func(_ context.Context, value Secret) error {
					calls.Add("callback:" + value.Selector())

					return nil
				})

				return bdg, cleanup
			},
			assert: func(t *testing.T, bdg *binding[Secret], calls *guardedCalls, cleanup func()) {
				t.Helper()

				require.Empty(t, calls.All())
				require.Len(t, bdg.callbacks, 1)

				bdg.publish(t.Context(), secrettypes.NewStringSecret("published", "published"))
				require.Equal(t, []string{"callback:published"}, calls.All())

				cleanup()
				require.Empty(t, bdg.callbacks)
			},
		},
		"nil callback is ignored": {
			setup: func(t *testing.T, usage *mocks.SecretUsageMock, _ *guardedCalls) (*binding[Secret], func()) {
				t.Helper()

				bdg := newBinding[Secret](
					bindingKey{
						kind:      bindingKindSecret,
						source:    "source",
						selector:  "selector",
						namespace: "namespace",
						scope:     referenceScopeInternal,
					},
					zerolog.Nop(),
					usage,
					nil,
				)

				return bdg, bdg.subscribe(nil)
			},
			assert: func(t *testing.T, bdg *binding[Secret], calls *guardedCalls, cleanup func()) {
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

			usage := mocks.NewSecretUsageMock(t)
			bdg, cleanup := tc.setup(t, usage, &calls)

			tc.assert(t, bdg, &calls, cleanup)
		})
	}
}

func TestBindingPublish(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, usage *mocks.SecretUsageMock, logs *bytes.Buffer, calls *guardedCalls) *binding[Secret]
		assert func(t *testing.T, bdg *binding[Secret], logs *bytes.Buffer, calls *guardedCalls)
	}{
		"stores value and notifies subscribers": {
			setup: func(t *testing.T, usage *mocks.SecretUsageMock, _ *bytes.Buffer, calls *guardedCalls) *binding[Secret] {
				t.Helper()

				usage.EXPECT().
					Track(secrettypes.NewStringSecret("published", "published")).
					Once()

				bdg := newBinding[Secret](
					bindingKey{
						kind:      bindingKindSecret,
						source:    "source",
						selector:  "selector",
						namespace: "namespace",
						scope:     referenceScopeInternal,
					},
					zerolog.Nop(),
					usage,
					nil,
				)
				bdg.subscribe(func(_ context.Context, value Secret) error {
					calls.Add("a:" + value.Selector())

					return nil
				})
				bdg.subscribe(func(_ context.Context, value Secret) error {
					calls.Add("b:" + value.Selector())

					return nil
				})

				return bdg
			},
			assert: func(t *testing.T, bdg *binding[Secret], _ *bytes.Buffer, calls *guardedCalls) {
				t.Helper()

				require.NoError(t, bdg.awaitReady(t.Context()))

				value, ok := bdg.peek()
				require.True(t, ok)
				require.Equal(t, secrettypes.NewStringSecret("published", "published"), value)

				require.ElementsMatch(t, []string{
					"a:published",
					"b:published",
				}, calls.All())
			},
		},
		"tracks new usage and untracks old usage": {
			setup: func(t *testing.T, usage *mocks.SecretUsageMock, _ *bytes.Buffer, _ *guardedCalls) *binding[Secret] {
				t.Helper()

				usage.EXPECT().
					Track(secrettypes.NewStringSecret("old", "old")).
					Once()
				usage.EXPECT().
					Track(secrettypes.NewStringSecret("published", "published")).
					Once()
				usage.EXPECT().
					Untrack(secrettypes.NewStringSecret("old", "old")).
					Once()

				bdg := newBinding[Secret](
					bindingKey{
						kind:      bindingKindSecret,
						source:    "source",
						selector:  "selector",
						namespace: "namespace",
						scope:     referenceScopeInternal,
					},
					zerolog.Nop(),
					usage,
					nil,
				)
				bdg.publish(t.Context(), secrettypes.NewStringSecret("old", "old"))

				return bdg
			},
			assert: func(t *testing.T, bdg *binding[Secret], _ *bytes.Buffer, _ *guardedCalls) {
				t.Helper()

				value, ok := bdg.peek()
				require.True(t, ok)
				require.Equal(t, secrettypes.NewStringSecret("published", "published"), value)
				require.NoError(t, bdg.awaitReady(t.Context()))
			},
		},
		"logs callback errors": {
			setup: func(t *testing.T, usage *mocks.SecretUsageMock, _ *bytes.Buffer, _ *guardedCalls) *binding[Secret] {
				t.Helper()

				usage.EXPECT().
					Track(secrettypes.NewStringSecret("published", "published")).
					Once()

				bdg := newBinding[Secret](
					bindingKey{
						kind:      bindingKindSecret,
						source:    "source",
						selector:  "selector",
						namespace: "namespace",
						scope:     referenceScopeInternal,
					},
					zerolog.Nop(),
					usage,
					nil,
				)
				bdg.subscribe(func(context.Context, Secret) error {
					return assert.AnError
				})

				return bdg
			},
			assert: func(t *testing.T, _ *binding[Secret], logs *bytes.Buffer, _ *guardedCalls) {
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

			usage := mocks.NewSecretUsageMock(t)
			bdg := tc.setup(t, usage, &logs, &calls)
			bdg.logger = zerolog.New(&logs)

			bdg.publish(t.Context(), secrettypes.NewStringSecret("published", "published"))

			tc.assert(t, bdg, &logs, &calls)
		})
	}
}

func TestBindingRun(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, usage *mocks.SecretUsageMock, logs *bytes.Buffer, calls *guardedCalls) *binding[Secret]
		assert func(t *testing.T, bdg *binding[Secret], logs *bytes.Buffer, calls *guardedCalls)
	}{
		"refreshes binding": {
			setup: func(t *testing.T, usage *mocks.SecretUsageMock, _ *bytes.Buffer, calls *guardedCalls) *binding[Secret] {
				t.Helper()

				usage.EXPECT().
					Track(secrettypes.NewStringSecret("refreshed", "refreshed")).
					Once()

				return newBinding(
					bindingKey{
						kind:      bindingKindSecret,
						source:    "source",
						selector:  "selector",
						namespace: "namespace",
						scope:     referenceScopeInternal,
					},
					zerolog.Nop(),
					usage,
					func(context.Context) (Secret, error) {
						calls.Add("resolve")

						return secrettypes.NewStringSecret("refreshed", "refreshed"), nil
					},
				)
			},
			assert: func(t *testing.T, bdg *binding[Secret], _ *bytes.Buffer, calls *guardedCalls) {
				t.Helper()

				require.NoError(t, bdg.awaitReady(t.Context()))

				require.Equal(t, []string{"resolve"}, calls.All())

				value, ok := bdg.peek()
				require.True(t, ok)
				require.Equal(t, secrettypes.NewStringSecret("refreshed", "refreshed"), value)
			},
		},
		"logs refresh error": {
			setup: func(t *testing.T, usage *mocks.SecretUsageMock, _ *bytes.Buffer, calls *guardedCalls) *binding[Secret] {
				t.Helper()

				return newBinding(
					bindingKey{
						kind:      bindingKindSecret,
						source:    "source",
						selector:  "selector",
						namespace: "namespace",
						scope:     referenceScopeInternal,
					},
					zerolog.Nop(),
					usage,
					func(context.Context) (Secret, error) {
						calls.Add("resolve")

						return nil, assert.AnError
					},
				)
			},
			assert: func(t *testing.T, _ *binding[Secret], logs *bytes.Buffer, calls *guardedCalls) {
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

			usage := mocks.NewSecretUsageMock(t)
			bdg := tc.setup(t, usage, &logs, &calls)
			bdg.logger = zerolog.New(&logs)

			bdg.Run()

			tc.assert(t, bdg, &logs, &calls)
		})
	}
}

func TestBindingUnschedule(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer

	bdg := newBinding[Secret](
		bindingKey{
			kind:      bindingKindSecret,
			source:    "source",
			selector:  "selector",
			namespace: "namespace",
			scope:     referenceScopeInternal,
		},
		zerolog.Nop(),
		mocks.NewSecretUsageMock(t),
		nil,
	)
	bdg.logger = zerolog.New(&logs)

	require.True(t, bdg.Schedule())

	bdg.Unschedule(assert.AnError)

	require.True(t, bdg.Schedule())
	require.Contains(t, logs.String(), "Failed scheduling secret binding refresh task")
}

func TestBindingStop(t *testing.T) {
	t.Parallel()

	usage := mocks.NewSecretUsageMock(t)
	usage.EXPECT().
		Track(secrettypes.NewStringSecret("current", "current")).
		Once()
	usage.EXPECT().
		Untrack(secrettypes.NewStringSecret("current", "current")).
		Once()

	bdg := newBinding[Secret](
		bindingKey{
			kind:      bindingKindSecret,
			source:    "source",
			selector:  "selector",
			namespace: "namespace",
			scope:     referenceScopeInternal,
		},
		zerolog.Nop(),
		usage,
		nil,
	)
	bdg.publish(t.Context(), secrettypes.NewStringSecret("current", "current"))
	bdg.subscribe(func(context.Context, Secret) error { return nil })

	require.NotEmpty(t, bdg.callbacks)

	bdg.stop()

	require.Empty(t, bdg.callbacks)
	require.False(t, bdg.Schedule())
}

func TestBindingAwaitReady(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, usage *mocks.SecretUsageMock) (*binding[Secret], context.Context)
		assert func(t *testing.T, err error)
	}{
		"returns nil after publish": {
			setup: func(t *testing.T, usage *mocks.SecretUsageMock) (*binding[Secret], context.Context) {
				t.Helper()

				usage.EXPECT().
					Track(secrettypes.NewStringSecret("ready", "ready")).
					Once()

				bdg := newBinding[Secret](
					bindingKey{
						kind:      bindingKindSecret,
						source:    "source",
						selector:  "selector",
						namespace: "namespace",
						scope:     referenceScopeInternal,
					},
					zerolog.Nop(),
					usage,
					nil,
				)
				bdg.publish(t.Context(), secrettypes.NewStringSecret("ready", "ready"))

				return bdg, t.Context()
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"returns context error if no value and no last error": {
			setup: func(t *testing.T, usage *mocks.SecretUsageMock) (*binding[Secret], context.Context) {
				t.Helper()

				ctx, cancel := context.WithCancel(t.Context())
				cancel()

				bdg := newBinding[Secret](
					bindingKey{
						kind:      bindingKindSecret,
						source:    "source",
						selector:  "selector",
						namespace: "namespace",
						scope:     referenceScopeInternal,
					},
					zerolog.Nop(),
					usage,
					nil,
				)

				return bdg, ctx
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, context.Canceled)
			},
		},
		"returns last error if no value and last error exists": {
			setup: func(t *testing.T, usage *mocks.SecretUsageMock) (*binding[Secret], context.Context) {
				t.Helper()

				bdg := newBinding(
					bindingKey{
						kind:      bindingKindSecret,
						source:    "source",
						selector:  "selector",
						namespace: "namespace",
						scope:     referenceScopeInternal,
					},
					zerolog.Nop(),
					usage,
					func(context.Context) (Secret, error) {
						return nil, assert.AnError
					},
				)

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

			usage := mocks.NewSecretUsageMock(t)
			bdg, ctx := tc.setup(t, usage)

			tc.assert(t, bdg.awaitReady(ctx))
		})
	}
}

func TestBindingLastErr(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, usage *mocks.SecretUsageMock) *binding[Secret]
		assert func(t *testing.T, bdg *binding[Secret])
	}{
		"resolve error stores last error": {
			setup: func(t *testing.T, usage *mocks.SecretUsageMock) *binding[Secret] {
				t.Helper()

				bdg := newBinding(
					bindingKey{
						kind:      bindingKindSecret,
						source:    "source",
						selector:  "selector",
						namespace: "namespace",
						scope:     referenceScopeInternal,
					},
					zerolog.Nop(),
					usage,
					func(context.Context) (Secret, error) {
						return nil, assert.AnError
					},
				)

				_, err := bdg.resolveOnce(t.Context(), resolveGroupCached)
				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)

				return bdg
			},
			assert: func(t *testing.T, bdg *binding[Secret]) {
				t.Helper()

				require.ErrorIs(t, bdg.getLastErr(), assert.AnError)
			},
		},
		"successful resolve clears last error": {
			setup: func(t *testing.T, usage *mocks.SecretUsageMock) *binding[Secret] {
				t.Helper()

				usage.EXPECT().
					Track(secrettypes.NewStringSecret("resolved", "resolved")).
					Once()

				bdg := newBinding(
					bindingKey{
						kind:      bindingKindSecret,
						source:    "source",
						selector:  "selector",
						namespace: "namespace",
						scope:     referenceScopeInternal,
					},
					zerolog.Nop(),
					usage,
					func(context.Context) (Secret, error) {
						return secrettypes.NewStringSecret("resolved", "resolved"), nil
					},
				)

				bdg.setLastErr(assert.AnError)

				_, err := bdg.resolveOnce(t.Context(), resolveGroupForced)
				require.NoError(t, err)

				return bdg
			},
			assert: func(t *testing.T, bdg *binding[Secret]) {
				t.Helper()

				require.NoError(t, bdg.getLastErr())
			},
		},
		"publish clears last error": {
			setup: func(t *testing.T, usage *mocks.SecretUsageMock) *binding[Secret] {
				t.Helper()

				usage.EXPECT().
					Track(secrettypes.NewStringSecret("published", "published")).
					Once()

				bdg := newBinding[Secret](
					bindingKey{
						kind:      bindingKindSecret,
						source:    "source",
						selector:  "selector",
						namespace: "namespace",
						scope:     referenceScopeInternal,
					},
					zerolog.Nop(),
					usage,
					nil,
				)
				bdg.setLastErr(assert.AnError)
				bdg.publish(t.Context(), secrettypes.NewStringSecret("published", "published"))

				return bdg
			},
			assert: func(t *testing.T, bdg *binding[Secret]) {
				t.Helper()

				require.NoError(t, bdg.getLastErr())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			usage := mocks.NewSecretUsageMock(t)
			bdg := tc.setup(t, usage)

			tc.assert(t, bdg)
		})
	}
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
