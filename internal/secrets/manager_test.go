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
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/secrets/registry"
	"github.com/dadrus/heimdall/internal/secrets/types"
	typemocks "github.com/dadrus/heimdall/internal/secrets/types/mocks"
)

func TestNewManager(t *testing.T) {
	t.Parallel()

	const testProviderType = "test-provider"

	factory := registry.FactoryFunc(func(
		_ app.Context,
		sourceName string,
		conf map[string]any,
	) (types.Provider, error) {
		provider := typemocks.NewProviderMock(t)
		provider.EXPECT().Name().Return(sourceName).Maybe()

		return provider, nil
	})

	registry.Register(testProviderType, factory)
	t.Cleanup(func() {
		registry.Unregister(testProviderType)
	})

	for uc, tc := range map[string]struct {
		config config.SecretManagement
		assert func(t *testing.T, err error, manager *manager)
	}{
		"supported provider type": {
			config: config.SecretManagement{
				"test": {Type: testProviderType, Config: map[string]any{"foo": "bar"}},
			},
			assert: func(t *testing.T, err error, mgr *manager) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, mgr)
				require.Contains(t, mgr.providers, "test")
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
			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Config().Return(&config.Configuration{SecretManagement: tc.config})
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
		assert   func(t *testing.T, err error, secret Secret)
	}{
		"delegates to configured provider": {
			provider: func(t *testing.T) *typemocks.ProviderMock {
				t.Helper()

				secret := types.NewStringSecret("tls", "first_entry", "value")

				provider := typemocks.NewProviderMock(t)
				provider.EXPECT().Name().Return("tls")
				provider.EXPECT().
					ResolveSecret(mock.Anything, types.Selector{Value: "first_entry"}).
					Return(secret, nil)

				return provider
			},
			assert: func(t *testing.T, err error, secret Secret) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, secret)
				require.Equal(t, "tls", secret.Source())
				require.Equal(t, "first_entry", secret.Ref())
				require.Equal(t, types.SecretKindString, secret.Kind())

				stringSecret, ok := secret.(types.StringSecret)
				require.True(t, ok)
				require.Equal(t, "value", stringSecret.String())
			},
		},
		"returns provider not found for unknown source": {
			provider: func(t *testing.T) *typemocks.ProviderMock {
				t.Helper()

				return nil
			},
			assert: func(t *testing.T, err error, _ Secret) {
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
				mgr = createManager(zerolog.Nop(), managedProvider{provider: prov})
			} else {
				mgr = createManager(zerolog.Nop())
			}

			secret, err := mgr.ResolveSecret(context.Background(), Reference{Source: "tls", Selector: "first_entry"})

			tc.assert(t, err, secret)
		})
	}
}

func TestManagerResolveCredentials(t *testing.T) {
	t.Parallel()

	type clientCredentials struct {
		ClientID     string `mapstructure:"client_id"`
		ClientSecret string `mapstructure:"client_secret"`
	}

	for uc, tc := range map[string]struct {
		provider func(t *testing.T) *typemocks.ProviderMock
		assert   func(t *testing.T, err error, credentials Credentials)
	}{
		"delegates to configured provider": {
			provider: func(t *testing.T) *typemocks.ProviderMock {
				t.Helper()

				credentials := types.NewCredentials("file", "client_credentials", map[string]types.Secret{
					"client_id": types.NewStringSecret(
						"file",
						"client_credentials/client_id",
						"foo",
					),
					"client_secret": types.NewStringSecret(
						"file",
						"client_credentials/client_secret",
						"bar",
					),
				})

				provider := typemocks.NewProviderMock(t)
				provider.EXPECT().Name().Return("file")
				provider.EXPECT().
					ResolveCredentials(mock.Anything, types.Selector{Value: "client_credentials"}).
					Return(credentials, nil)

				return provider
			},
			assert: func(t *testing.T, err error, credentials Credentials) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, credentials)

				var decoded clientCredentials
				require.NoError(t, credentials.Decode(&decoded))

				require.Equal(t, "foo", decoded.ClientID)
				require.Equal(t, "bar", decoded.ClientSecret)
			},
		},
		"returns provider not found for unknown source": {
			provider: func(t *testing.T) *typemocks.ProviderMock {
				t.Helper()

				return nil
			},
			assert: func(t *testing.T, err error, _ Credentials) {
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
				mgr = createManager(zerolog.Nop(), managedProvider{provider: prov})
			} else {
				mgr = createManager(zerolog.Nop())
			}

			credentials, err := mgr.ResolveCredentials(
				context.Background(),
				Reference{Source: "file", Selector: "client_credentials"})

			tc.assert(t, err, credentials)
		})
	}
}

func TestManagerSubscribe(t *testing.T) {
	t.Parallel()

	t.Run("returns error for unknown source", func(t *testing.T) {
		t.Parallel()

		mgr := createManager(zerolog.Nop())
		unsubscribe, err := mgr.Subscribe(
			Reference{Source: "unknown", Selector: "ref"},
			func(context.Context) error { return nil },
		)
		require.Nil(t, unsubscribe)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrProviderNotFound)
	})

	t.Run("returns error for nil callback", func(t *testing.T) {
		t.Parallel()

		provider := typemocks.NewProviderMock(t)
		provider.EXPECT().Name().Return("pem")
		mgr := createManager(zerolog.Nop(), managedProvider{provider: provider})

		unsubscribe, err := mgr.Subscribe(Reference{Source: "pem", Selector: "entry"}, nil)
		require.Nil(t, unsubscribe)
		require.Error(t, err)
	})

	t.Run("invokes callback for matching source and ref", func(t *testing.T) {
		t.Parallel()

		mgr, trigger := newStartedManagerWithChangeTrigger(t, "pem")
		called := make(chan struct{}, 1)

		unsubscribe, err := mgr.Subscribe(
			Reference{Source: "pem", Selector: "entry-a"},
			func(context.Context) error {
				called <- struct{}{}

				return nil
			},
		)
		require.NoError(t, err)

		defer unsubscribe()

		trigger(types.ChangeEvent{Source: "pem", Selectors: []string{"entry-a"}})

		select {
		case <-called:
		case <-time.After(500 * time.Millisecond):
			t.Fatal("callback not called")
		}
	})

	t.Run("does not invoke callback for non matching ref", func(t *testing.T) {
		t.Parallel()

		mgr, trigger := newStartedManagerWithChangeTrigger(t, "pem")
		called := make(chan struct{}, 1)

		unsubscribe, err := mgr.Subscribe(
			Reference{Source: "pem", Selector: "entry-a"},
			func(context.Context) error {
				called <- struct{}{}

				return nil
			},
		)
		require.NoError(t, err)

		defer unsubscribe()

		trigger(types.ChangeEvent{Source: "pem", Selectors: []string{"entry-b"}})

		select {
		case <-called:
			t.Fatal("callback unexpectedly called")
		case <-time.After(200 * time.Millisecond):
		}
	})

	t.Run("fan-out for empty refs event", func(t *testing.T) {
		t.Parallel()

		mgr, trigger := newStartedManagerWithChangeTrigger(t, "pem")
		calledA := make(chan struct{}, 1)
		calledB := make(chan struct{}, 1)

		unsubA, err := mgr.Subscribe(
			Reference{Source: "pem", Selector: "entry-a"},
			func(context.Context) error {
				calledA <- struct{}{}

				return nil
			},
		)
		require.NoError(t, err)

		defer unsubA()

		unsubB, err := mgr.Subscribe(
			Reference{Source: "pem", Selector: "entry-b"},
			func(context.Context) error {
				calledB <- struct{}{}

				return nil
			},
		)
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

		unsubscribe, err := mgr.Subscribe(
			Reference{Source: "pem", Selector: "entry-a"},
			func(context.Context) error {
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
			},
		)
		require.NoError(t, err)

		defer unsubscribe()

		trigger(types.ChangeEvent{Source: "pem", Selectors: []string{"entry-a"}})
		time.Sleep(10 * time.Millisecond)
		trigger(types.ChangeEvent{Source: "pem", Selectors: []string{"entry-a"}})

		require.Eventually(t, func() bool { return atomic.LoadInt32(&callCount) == 2 }, time.Second, 10*time.Millisecond)
		require.EqualValues(t, 1, atomic.LoadInt32(&maxConcurrent))
	})

	t.Run("does not retry callback on callback error", func(t *testing.T) {
		t.Parallel()

		var callCount int32

		mgr, trigger := newStartedManagerWithChangeTrigger(t, "pem")

		unsubscribe, err := mgr.Subscribe(
			Reference{Source: "pem", Selector: "entry-a"},
			func(context.Context) error {
				atomic.AddInt32(&callCount, 1)

				return errors.New("boom")
			},
		)
		require.NoError(t, err)

		defer unsubscribe()

		trigger(types.ChangeEvent{Source: "pem", Selectors: []string{"entry-a"}})
		require.Eventually(t, func() bool { return atomic.LoadInt32(&callCount) == 1 }, time.Second, 10*time.Millisecond)

		time.Sleep(200 * time.Millisecond)
		require.EqualValues(t, 1, atomic.LoadInt32(&callCount))
	})

	t.Run("does not invoke callback after unsubscribe", func(t *testing.T) {
		t.Parallel()

		mgr, trigger := newStartedManagerWithChangeTrigger(t, "pem")
		called := make(chan struct{}, 1)

		unsubscribe, err := mgr.Subscribe(
			Reference{Source: "pem", Selector: "entry-a"},
			func(context.Context) error {
				called <- struct{}{}

				return nil
			},
		)
		require.NoError(t, err)

		unsubscribe()
		trigger(types.ChangeEvent{Source: "pem", Selectors: []string{"entry-a"}})

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

		unsubA, err := mgr.Subscribe(
			Reference{Source: "pem", Selector: "entry-a"},
			func(context.Context) error {
				calledA <- struct{}{}

				return nil
			},
		)
		require.NoError(t, err)

		unsubB, err := mgr.Subscribe(
			Reference{Source: "pem", Selector: "entry-a"},
			func(context.Context) error {
				calledB <- struct{}{}

				return nil
			},
		)
		require.NoError(t, err)

		defer unsubB()

		unsubA()
		trigger(types.ChangeEvent{Source: "pem", Selectors: []string{"entry-a"}})

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

		unsubscribe, err := mgr.Subscribe(
			Reference{Source: "pem", Selector: "entry-a"},
			func(context.Context) error { return nil },
		)
		require.NoError(t, err)

		err = mgr.Stop(context.Background())
		require.NoError(t, err)

		require.NotPanics(t, func() { unsubscribe() })
	})

	t.Run("unsubscribe can be called twice without panic", func(t *testing.T) {
		t.Parallel()

		mgr, _ := newStartedManagerWithChangeTrigger(t, "pem")

		unsubscribe, err := mgr.Subscribe(
			Reference{Source: "pem", Selector: "entry-a"},
			func(context.Context) error { return nil },
		)
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

		mgr := createManager(zerolog.Nop(), managedProvider{provider: provider})

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
		mgr := createManager(zerolog.Nop(), managedProvider{provider: provider})

		err := mgr.Start(context.Background())
		require.NoError(t, err)

		err = mgr.Stop(context.Background())
		require.NoError(t, err)
	})

	t.Run("stops already started providers when startup fails", func(t *testing.T) {
		var (
			started atomic.Int32
			stopped atomic.Int32
		)

		mgr := createManager(
			zerolog.Nop(),
			managedProvider{provider: &startStopProvider{name: "a", started: &started, stopped: &stopped}},
			managedProvider{provider: &startStopProvider{name: "b", started: &started, stopped: &stopped}},
			managedProvider{provider: &startStopProvider{name: "c", startErr: errors.New("boom")}},
		)

		err := mgr.Start(context.Background())

		require.Error(t, err)
		require.ErrorContains(t, err, "boom")
		require.Equal(t, started.Load(), stopped.Load())
	})

	t.Run("stops subscriber callbacks on manager stop", func(t *testing.T) {
		t.Parallel()

		var callCount int32

		mgr, trigger := newStartedManagerWithChangeTrigger(t, "pem")

		_, err := mgr.Subscribe(
			Reference{Source: "pem", Selector: "entry-a"},
			func(context.Context) error {
				atomic.AddInt32(&callCount, 1)

				return errors.New("boom")
			},
		)
		require.NoError(t, err)

		trigger(types.ChangeEvent{Source: "pem", Selectors: []string{"entry-a"}})

		require.Eventually(t, func() bool {
			return atomic.LoadInt32(&callCount) == 1
		}, time.Second, 10*time.Millisecond)

		err = mgr.Stop(context.Background())
		require.NoError(t, err)

		trigger(types.ChangeEvent{Source: "pem", Selectors: []string{"entry-a"}})

		time.Sleep(200 * time.Millisecond)
		require.EqualValues(t, 1, atomic.LoadInt32(&callCount))
	})

	t.Run("returns provider stop error", func(t *testing.T) {
		t.Parallel()

		first := typemocks.NewProviderMock(t)
		first.EXPECT().Name().Return("first")
		first.EXPECT().Stop(mock.Anything).Return(errors.New("boom")).Once()

		second := typemocks.NewProviderMock(t)
		second.EXPECT().Name().Return("second")
		second.EXPECT().Stop(mock.Anything).Return(nil).Once()

		mgr := createManager(zerolog.Nop(),
			managedProvider{provider: first},
			managedProvider{provider: second},
		)

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

	mgr := createManager(zerolog.Nop(), managedProvider{provider: provider})

	err := mgr.Start(context.Background())
	require.NoError(t, err)

	return mgr, func(evt types.ChangeEvent) {
		require.NotNil(t, onChange)
		onChange(evt)
	}
}

type startStopProvider struct {
	name     string
	startErr error
	started  *atomic.Int32
	stopped  *atomic.Int32
}

func (p *startStopProvider) Name() string { return p.name }

func (p *startStopProvider) Type() string { return "test" }

func (p *startStopProvider) ResolveSecret(_ context.Context, _ types.Selector) (types.Secret, error) {
	return nil, errors.New("not implemented")
}

func (p *startStopProvider) ResolveCredentials(_ context.Context, _ types.Selector) (types.Credentials, error) {
	return nil, errors.New("not implemented")
}

func (p *startStopProvider) ResolveSecretSet(_ context.Context, _ types.Selector) ([]Secret, error) {
	return nil, errors.New("not implemented")
}

func (p *startStopProvider) Start(context.Context, func(types.ChangeEvent)) error {
	if p.startErr != nil {
		return p.startErr
	}

	if p.started != nil {
		p.started.Add(1)
	}

	return nil
}

func (p *startStopProvider) Stop(context.Context) error {
	if p.stopped != nil {
		p.stopped.Add(1)
	}

	return nil
}
