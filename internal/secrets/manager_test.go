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

package secrets_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/secrets"
	"github.com/dadrus/heimdall/internal/secrets/types"
	typemocks "github.com/dadrus/heimdall/internal/secrets/types/mocks"
)

type watchableProvider struct {
	*typemocks.ProviderMock
	*typemocks.WatchableMock
}

func TestManagerResolveSecret(t *testing.T) {
	t.Parallel()

	t.Run("delegates to configured provider", func(t *testing.T) {
		t.Parallel()

		provider := typemocks.NewProviderMock(t)
		provider.EXPECT().Name().Return("tls")
		provider.EXPECT().
			ResolveSecret(mock.Anything, "first_entry").
			Return(types.Secret{Type: types.SecretTypePlain, Value: "value"}, nil)

		manager := secrets.NewManager(provider)

		secret, err := manager.ResolveSecret(context.Background(), "tls", "first_entry")
		require.NoError(t, err)

		value, err := secret.AsString()
		require.NoError(t, err)
		require.Equal(t, "value", value)
	})

	t.Run("returns provider not found for unknown source", func(t *testing.T) {
		t.Parallel()

		manager := secrets.NewManager()

		secret, err := manager.ResolveSecret(context.Background(), "unknown", "ref")
		require.Equal(t, types.Secret{}, secret)
		require.Error(t, err)
		require.ErrorIs(t, err, secrets.ErrProviderNotFound)
	})
}

func TestManagerResolveSecrets(t *testing.T) {
	t.Parallel()

	provider := typemocks.NewProviderMock(t)
	provider.EXPECT().Name().Return("file")
	provider.EXPECT().
		ResolveSecrets(mock.Anything, "client_credentials", "client_id", "client_secret").
		Return(map[string]types.Secret{
			"client_id":     {Type: types.SecretTypePlain, Value: "foo"},
			"client_secret": {Type: types.SecretTypePlain, Value: "bar"},
		}, nil)

	manager := secrets.NewManager(provider)

	values, err := manager.ResolveSecrets(
		context.Background(),
		"file",
		"client_credentials",
		"client_id",
		"client_secret",
	)
	require.NoError(t, err)

	clientID, err := values["client_id"].AsString()
	require.NoError(t, err)
	clientSecret, err := values["client_secret"].AsString()
	require.NoError(t, err)
	require.Equal(t, "foo", clientID)
	require.Equal(t, "bar", clientSecret)
}

func TestManagerSubscribe(t *testing.T) {
	t.Parallel()

	t.Run("returns error for unknown source", func(t *testing.T) {
		t.Parallel()

		manager := secrets.NewManager()
		unsubscribe, err := manager.Subscribe("unknown", "ref", func(context.Context) error { return nil })
		require.Nil(t, unsubscribe)
		require.Error(t, err)
		require.ErrorIs(t, err, secrets.ErrProviderNotFound)
	})

	t.Run("returns error for nil callback", func(t *testing.T) {
		t.Parallel()

		provider := typemocks.NewProviderMock(t)
		provider.EXPECT().Name().Return("pem")
		manager := secrets.NewManager(provider)

		unsubscribe, err := manager.Subscribe("pem", "entry", nil)
		require.Nil(t, unsubscribe)
		require.Error(t, err)
	})

	t.Run("invokes callback for matching source and ref", func(t *testing.T) {
		t.Parallel()

		manager, trigger := newWatchableManager(t, "pem")
		called := make(chan struct{}, 1)

		unsubscribe, err := manager.Subscribe("pem", "entry-a", func(context.Context) error {
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

		manager, trigger := newWatchableManager(t, "pem")
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

		manager, trigger := newWatchableManager(t, "pem")
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

		manager, trigger := newWatchableManager(t, "pem")
		var maxConcurrent, currentCalls, callCount int32

		unsubscribe, err := manager.Subscribe("pem", "entry-a", func(context.Context) error {
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

		manager, trigger := newWatchableManager(t, "pem")
		var callCount int32

		unsubscribe, err := manager.Subscribe("pem", "entry-a", func(context.Context) error {
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

	t.Run("registers provider watch only once per source", func(t *testing.T) {
		t.Parallel()

		manager, _ := newWatchableManager(t, "pem")

		unsubA, err := manager.Subscribe("pem", "entry-a", func(context.Context) error { return nil })
		require.NoError(t, err)
		defer unsubA()

		unsubB, err := manager.Subscribe("pem", "entry-b", func(context.Context) error { return nil })
		require.NoError(t, err)
		defer unsubB()
	})

	t.Run("does not invoke callback after unsubscribe", func(t *testing.T) {
		t.Parallel()

		manager, trigger := newWatchableManager(t, "pem")
		called := make(chan struct{}, 1)

		unsubscribe, err := manager.Subscribe("pem", "entry-a", func(context.Context) error {
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
}

func newWatchableManager(t *testing.T, source string) (secrets.Manager, func(types.ChangeEvent)) {
	t.Helper()

	var onChange func(types.ChangeEvent)

	provider := typemocks.NewProviderMock(t)
	provider.EXPECT().Name().Return(source)

	watchable := typemocks.NewWatchableMock(t)
	watchable.EXPECT().
		Watch(mock.Anything, mock.Anything).
		Run(func(_ context.Context, cb func(types.ChangeEvent)) { onChange = cb }).
		Return(nil).
		Once()

	manager := secrets.NewManager(&watchableProvider{
		ProviderMock:  provider,
		WatchableMock: watchable,
	})

	return manager, func(evt types.ChangeEvent) {
		require.NotNil(t, onChange)
		onChange(evt)
	}
}
