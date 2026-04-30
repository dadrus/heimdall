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
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	_ "github.com/dadrus/heimdall/internal/secrets/providers/pem"
	"github.com/dadrus/heimdall/internal/secrets/types"
	typemocks "github.com/dadrus/heimdall/internal/secrets/types/mocks"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/x/pkix/pemx"
)

func TestNewManager(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	data, err := pemx.BuildPEM(pemx.WithRSAPrivateKey(key,
		pemx.WithHeader("X-Key-ID", "foo")))
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "keys.pem")
	err = os.WriteFile(path, data, 0o600)
	require.NoError(t, err)

	for uc, tc := range map[string]struct {
		config config.SecretManagement
		assert func(t *testing.T, err error, manager *manager)
	}{
		"supported provider type": {
			config: config.SecretManagement{
				"tls": {Type: "pem", Config: map[string]any{"path": path}},
			},
			assert: func(t *testing.T, err error, mgr *manager) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, mgr)
			},
		},
		"unsupported provider type": {
			config: config.SecretManagement{
				"bad": {Type: "does-not-exist"},
			},
			assert: func(t *testing.T, err error, _ *manager) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrUnsupportedProviderType)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			validator, err := validation.NewValidator()
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Config().Return(&config.Configuration{SecretManagement: tc.config})
			appCtx.EXPECT().Validator().Return(validator).Maybe()
			appCtx.EXPECT().Logger().Return(zerolog.Nop()).Maybe()

			mgr, err := newManager(appCtx)

			tc.assert(t, err, mgr)
		})
	}
}

func TestManagerResolveSecret(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		provider func(t *testing.T) *typemocks.ProviderMock
		assert   func(t *testing.T, err error, secret types.Secret)
	}{
		"delegates to configured provider": {
			provider: func(t *testing.T) *typemocks.ProviderMock {
				t.Helper()

				provider := typemocks.NewProviderMock(t)
				provider.EXPECT().Name().Return("tls")
				provider.EXPECT().
					ResolveSecret(mock.Anything, "first_entry").
					Return(types.Secret{Type: types.SecretTypePlain, Value: "value"}, nil)

				return provider
			},
			assert: func(t *testing.T, err error, secret types.Secret) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, types.SecretTypePlain, secret.Type)
				require.Equal(t, "value", secret.Value)
			},
		},
		"returns provider not found for unknown source": {
			provider: func(t *testing.T) *typemocks.ProviderMock {
				t.Helper()

				return nil
			},
			assert: func(t *testing.T, err error, _ types.Secret) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrProviderNotFound)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			var mgr *manager

			prov := tc.provider(t)
			if prov != nil {
				mgr = createManager(zerolog.Nop(), prov)
			} else {
				mgr = createManager(zerolog.Nop())
			}

			secret, err := mgr.ResolveSecret(context.Background(), "tls", "first_entry")

			tc.assert(t, err, secret)
		})
	}
}

func TestManagerResolveSecrets(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		provider func(t *testing.T) *typemocks.ProviderMock
		assert   func(t *testing.T, err error, secrets map[string]types.Secret)
	}{
		"delegates to configured provider": {
			provider: func(t *testing.T) *typemocks.ProviderMock {
				t.Helper()

				provider := typemocks.NewProviderMock(t)
				provider.EXPECT().Name().Return("file")
				provider.EXPECT().
					ResolveSecrets(mock.Anything, "client_credentials", "client_id", "client_secret").
					Return(map[string]types.Secret{
						"client_id":     {Type: types.SecretTypePlain, Value: "foo"},
						"client_secret": {Type: types.SecretTypePlain, Value: "bar"},
					}, nil)

				return provider
			},
			assert: func(t *testing.T, err error, secrets map[string]types.Secret) {
				t.Helper()

				require.NoError(t, err)

				clientID, err := secrets["client_id"].AsString()
				require.NoError(t, err)
				clientSecret, err := secrets["client_secret"].AsString()
				require.NoError(t, err)
				require.Equal(t, "foo", clientID)
				require.Equal(t, "bar", clientSecret)
			},
		},
		"returns provider not found for unknown source": {
			provider: func(t *testing.T) *typemocks.ProviderMock {
				t.Helper()

				return nil
			},
			assert: func(t *testing.T, err error, _ map[string]types.Secret) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrProviderNotFound)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			var mgr *manager

			prov := tc.provider(t)
			if prov != nil {
				mgr = createManager(zerolog.Nop(), prov)
			} else {
				mgr = createManager(zerolog.Nop())
			}

			values, err := mgr.ResolveSecrets(
				context.Background(),
				"file",
				"client_credentials",
				"client_id",
				"client_secret",
			)

			tc.assert(t, err, values)
		})
	}
}

func TestManagerSubscribe(t *testing.T) {
	t.Parallel()

	t.Run("returns error for unknown source", func(t *testing.T) {
		t.Parallel()

		mgr := createManager(zerolog.Nop())
		unsubscribe, err := mgr.Subscribe("unknown", "ref", func(context.Context) error { return nil })
		require.Nil(t, unsubscribe)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrProviderNotFound)
	})

	t.Run("returns error for nil callback", func(t *testing.T) {
		t.Parallel()

		provider := typemocks.NewProviderMock(t)
		provider.EXPECT().Name().Return("pem")
		mgr := createManager(zerolog.Nop(), provider)

		unsubscribe, err := mgr.Subscribe("pem", "entry", nil)
		require.Nil(t, unsubscribe)
		require.Error(t, err)
	})

	t.Run("invokes callback for matching source and ref", func(t *testing.T) {
		t.Parallel()

		mgr, trigger := newStartedManagerWithChangeTrigger(t, "pem")
		called := make(chan struct{}, 1)

		unsubscribe, err := mgr.Subscribe("pem", "entry-a", func(context.Context) error {
			called <- struct{}{}

			return nil
		})
		require.NoError(t, err)

		defer unsubscribe()

		trigger(types.ChangeEvent{Source: "pem", Refs: []string{"entry-a"}})

		select {
		case <-called:
		case <-time.After(500 * time.Millisecond):
			t.Fatal("callback not called")
		}
	})

	t.Run("does not invoke callback for non matching ref", func(t *testing.T) {
		t.Parallel()

		manager, trigger := newStartedManagerWithChangeTrigger(t, "pem")
		called := make(chan struct{}, 1)

		unsubscribe, err := manager.Subscribe("pem", "entry-a", func(context.Context) error {
			called <- struct{}{}

			return nil
		})
		require.NoError(t, err)

		defer unsubscribe()

		trigger(types.ChangeEvent{Source: "pem", Refs: []string{"entry-b"}})

		select {
		case <-called:
			t.Fatal("callback unexpectedly called")
		case <-time.After(200 * time.Millisecond):
		}
	})

	t.Run("fan-out for empty refs event", func(t *testing.T) {
		t.Parallel()

		manager, trigger := newStartedManagerWithChangeTrigger(t, "pem")
		calledA := make(chan struct{}, 1)
		calledB := make(chan struct{}, 1)

		unsubA, err := manager.Subscribe("pem", "entry-a", func(context.Context) error {
			calledA <- struct{}{}

			return nil
		})
		require.NoError(t, err)

		defer unsubA()

		unsubB, err := manager.Subscribe("pem", "entry-b", func(context.Context) error {
			calledB <- struct{}{}

			return nil
		})
		require.NoError(t, err)

		defer unsubB()

		trigger(types.ChangeEvent{Source: "pem"})

		select {
		case <-calledA:
		case <-time.After(500 * time.Millisecond):
			t.Fatal("callback A not called")
		}

		select {
		case <-calledB:
		case <-time.After(500 * time.Millisecond):
			t.Fatal("callback B not called")
		}
	})

	t.Run("serializes callback execution per source/ref", func(t *testing.T) {
		t.Parallel()

		var maxConcurrent, currentCalls, callCount int32

		mgr, trigger := newStartedManagerWithChangeTrigger(t, "pem")

		unsubscribe, err := mgr.Subscribe("pem", "entry-a", func(context.Context) error {
			calls := atomic.AddInt32(&currentCalls, 1)

			for {
				old := atomic.LoadInt32(&maxConcurrent)
				if calls <= old || atomic.CompareAndSwapInt32(&maxConcurrent, old, calls) {
					break
				}
			}

			time.Sleep(50 * time.Millisecond)
			atomic.AddInt32(&callCount, 1)
			atomic.AddInt32(&currentCalls, -1)

			return nil
		})
		require.NoError(t, err)

		defer unsubscribe()

		trigger(types.ChangeEvent{Source: "pem", Refs: []string{"entry-a"}})
		time.Sleep(10 * time.Millisecond)
		trigger(types.ChangeEvent{Source: "pem", Refs: []string{"entry-a"}})

		require.Eventually(t, func() bool { return atomic.LoadInt32(&callCount) == 2 }, time.Second, 10*time.Millisecond)
		require.EqualValues(t, 1, atomic.LoadInt32(&maxConcurrent))
	})

	t.Run("does not retry callback on callback error", func(t *testing.T) {
		t.Parallel()

		var callCount int32

		mgr, trigger := newStartedManagerWithChangeTrigger(t, "pem")

		unsubscribe, err := mgr.Subscribe("pem", "entry-a", func(context.Context) error {
			atomic.AddInt32(&callCount, 1)

			return errors.New("boom")
		})
		require.NoError(t, err)

		defer unsubscribe()

		trigger(types.ChangeEvent{Source: "pem", Refs: []string{"entry-a"}})
		require.Eventually(t, func() bool { return atomic.LoadInt32(&callCount) == 1 }, time.Second, 10*time.Millisecond)

		time.Sleep(200 * time.Millisecond)
		require.EqualValues(t, 1, atomic.LoadInt32(&callCount))
	})

	t.Run("does not invoke callback after unsubscribe", func(t *testing.T) {
		t.Parallel()

		mgr, trigger := newStartedManagerWithChangeTrigger(t, "pem")
		called := make(chan struct{}, 1)

		unsubscribe, err := mgr.Subscribe("pem", "entry-a", func(context.Context) error {
			called <- struct{}{}

			return nil
		})
		require.NoError(t, err)

		unsubscribe()
		trigger(types.ChangeEvent{Source: "pem", Refs: []string{"entry-a"}})

		select {
		case <-called:
			t.Fatal("callback unexpectedly called after unsubscribe")
		case <-time.After(200 * time.Millisecond):
		}
	})

	t.Run("keeps binding when one of multiple subscribers unsubscribes", func(t *testing.T) {
		t.Parallel()

		mgr, trigger := newStartedManagerWithChangeTrigger(t, "pem")
		calledA := make(chan struct{}, 1)
		calledB := make(chan struct{}, 1)

		unsubA, err := mgr.Subscribe("pem", "entry-a", func(context.Context) error {
			calledA <- struct{}{}

			return nil
		})
		require.NoError(t, err)

		unsubB, err := mgr.Subscribe("pem", "entry-a", func(context.Context) error {
			calledB <- struct{}{}

			return nil
		})
		require.NoError(t, err)

		defer unsubB()

		unsubA()
		trigger(types.ChangeEvent{Source: "pem", Refs: []string{"entry-a"}})

		select {
		case <-calledA:
			t.Fatal("first callback unexpectedly called")
		case <-time.After(200 * time.Millisecond):
		}

		select {
		case <-calledB:
		case <-time.After(500 * time.Millisecond):
			t.Fatal("second callback not called")
		}
	})

	t.Run("unsubscribe is no-op after manager stop", func(t *testing.T) {
		t.Parallel()

		mgr, _ := newStartedManagerWithChangeTrigger(t, "pem")

		unsubscribe, err := mgr.Subscribe("pem", "entry-a", func(context.Context) error {
			return nil
		})
		require.NoError(t, err)

		err = mgr.Stop(context.Background())
		require.NoError(t, err)

		require.NotPanics(t, func() { unsubscribe() })
	})

	t.Run("unsubscribe can be called twice without panic", func(t *testing.T) {
		t.Parallel()

		mgr, _ := newStartedManagerWithChangeTrigger(t, "pem")

		unsubscribe, err := mgr.Subscribe("pem", "entry-a", func(context.Context) error {
			return nil
		})
		require.NoError(t, err)

		require.NotPanics(t, func() { unsubscribe() })
		require.NotPanics(t, func() { unsubscribe() })
	})
}

func TestManagerStartStop(t *testing.T) {
	t.Parallel()

	t.Run("starts providers only once", func(t *testing.T) {
		provider := typemocks.NewProviderMock(t)
		provider.EXPECT().Name().Return("pem")
		provider.EXPECT().Start(mock.Anything, mock.Anything).Return(nil).Once()
		provider.EXPECT().Stop(mock.Anything).Return(nil).Once()

		mgr := createManager(zerolog.Nop(), provider)

		err := mgr.Start(context.Background())
		require.NoError(t, err)

		err = mgr.Start(context.Background())
		require.NoError(t, err)

		err = mgr.Stop(context.Background())
		require.NoError(t, err)
	})

	t.Run("propagates lifecycle start and stop", func(t *testing.T) {
		provider := typemocks.NewProviderMock(t)
		provider.EXPECT().Name().Return("pem")
		provider.EXPECT().Start(mock.Anything, mock.Anything).Return(nil).Once()
		provider.EXPECT().Stop(mock.Anything).Return(nil).Once()
		mgr := createManager(zerolog.Nop(), provider)

		err := mgr.Start(context.Background())
		require.NoError(t, err)

		err = mgr.Stop(context.Background())
		require.NoError(t, err)
	})

	t.Run("stops already started providers when startup fails", func(t *testing.T) {
		first := typemocks.NewProviderMock(t)
		first.EXPECT().Name().Return("first")
		first.EXPECT().Start(mock.Anything, mock.Anything).Return(nil).Once()
		first.EXPECT().Stop(mock.Anything).Return(nil).Once()

		second := typemocks.NewProviderMock(t)
		second.EXPECT().Name().Return("second")
		second.EXPECT().Start(mock.Anything, mock.Anything).Return(errors.New("boom")).Once()

		mgr := createManager(zerolog.Nop(), first, second)

		err := mgr.Start(context.Background())
		require.Error(t, err)
	})

	t.Run("stops subscriber callbacks on manager stop", func(t *testing.T) {
		var callCount int32

		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		data, err := pemx.BuildPEM(pemx.WithRSAPrivateKey(key,
			pemx.WithHeader("X-Key-ID", "foo")))
		require.NoError(t, err)

		path := filepath.Join(t.TempDir(), "keys.pem")
		err = os.WriteFile(path, data, 0o600)
		require.NoError(t, err)

		validator, err := validation.NewValidator()
		require.NoError(t, err)

		appCtx := app.NewContextMock(t)
		appCtx.EXPECT().Config().Return(
			&config.Configuration{
				SecretManagement: config.SecretManagement{
					"tls": {
						Type:   "pem",
						Config: map[string]any{"path": path, "watch": true},
					},
				},
			})
		appCtx.EXPECT().Validator().Return(validator).Maybe()
		appCtx.EXPECT().Logger().Return(zerolog.Nop())

		mgr, err := newManager(appCtx)
		require.NoError(t, err)

		err = mgr.Start(context.Background())
		require.NoError(t, err)

		_, err = mgr.Subscribe("tls", "foo", func(context.Context) error {
			atomic.AddInt32(&callCount, 1)

			return errors.New("boom")
		})
		require.NoError(t, err)

		// update the key
		key, err = rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		data, err = pemx.BuildPEM(pemx.WithRSAPrivateKey(key,
			pemx.WithHeader("X-Key-ID", "foo")))
		require.NoError(t, err)

		err = os.WriteFile(path, data, 0o600)
		require.NoError(t, err)

		require.Eventually(t, func() bool {
			return atomic.LoadInt32(&callCount) > 0
		}, time.Second, 25*time.Millisecond)

		updatesBeforeStop := atomic.LoadInt32(&callCount)

		err = mgr.Stop(context.Background())
		require.NoError(t, err)

		// update once more after stop
		key, err = rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		data, err = pemx.BuildPEM(pemx.WithRSAPrivateKey(key,
			pemx.WithHeader("X-Key-ID", "foo")))
		require.NoError(t, err)

		err = os.WriteFile(path, data, 0o600)
		require.NoError(t, err)

		time.Sleep(300 * time.Millisecond)
		require.Equal(t, updatesBeforeStop, atomic.LoadInt32(&callCount))
	})

	t.Run("returns provider stop error", func(t *testing.T) {
		t.Parallel()

		first := typemocks.NewProviderMock(t)
		first.EXPECT().Name().Return("first")
		first.EXPECT().Stop(mock.Anything).Return(errors.New("boom")).Once()

		second := typemocks.NewProviderMock(t)
		second.EXPECT().Name().Return("second")
		second.EXPECT().Stop(mock.Anything).Return(nil).Once()

		mgr := createManager(zerolog.Nop(), first, second)

		err := mgr.Stop(context.Background())
		require.Error(t, err)
		require.ErrorContains(t, err, "boom")
	})
}

//nolint:unparam
func newStartedManagerWithChangeTrigger(t *testing.T, source string) (*manager, func(types.ChangeEvent)) {
	t.Helper()

	var onChange func(types.ChangeEvent)

	provider := typemocks.NewProviderMock(t)
	provider.EXPECT().Name().Return(source)
	provider.EXPECT().Start(mock.Anything, mock.Anything).
		Run(func(_ context.Context, cb func(types.ChangeEvent)) {
			onChange = cb
		}).
		Return(nil).
		Once()
	provider.EXPECT().Stop(mock.Anything).Return(nil).Maybe()

	mgr := createManager(zerolog.Nop(), provider)

	err := mgr.Start(context.Background())
	require.NoError(t, err)

	return mgr, func(evt types.ChangeEvent) {
		require.NotNil(t, onChange)
		onChange(evt)
	}
}
