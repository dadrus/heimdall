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
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/secrets"
	"github.com/dadrus/heimdall/internal/secrets/mocks"
	"github.com/dadrus/heimdall/internal/secrets/types"
)

func TestNewSecretInformer(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, resolver *mocks.ResolverMock, handle *mocks.SecretHandleMock)
		opts   []secrets.InformerOptions[string]
		assert func(t *testing.T, informer *secrets.SecretInformer[string], err error)
	}{
		"creates informer without options": {
			setup: func(t *testing.T, resolver *mocks.ResolverMock, handle *mocks.SecretHandleMock) {
				t.Helper()

				resolver.EXPECT().
					Secret(
						mock.Anything,
						secrets.Reference{Source: "src", Selector: "selector"},
					).
					Return(handle, nil)
			},
			assert: func(t *testing.T, informer *secrets.SecretInformer[string], err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, informer)
			},
		},
		"creates informer with eager mode": {
			opts: []secrets.InformerOptions[string]{
				{
					Converter: func(secret secrets.Secret) (string, error) {
						return secret.Selector(), nil
					},
					ResolveMode: secrets.ResolveEager,
				},
			},
			setup: func(t *testing.T, resolver *mocks.ResolverMock, handle *mocks.SecretHandleMock) {
				t.Helper()

				resolver.EXPECT().
					Secret(
						mock.Anything,
						secrets.Reference{Source: "src", Selector: "selector"},
						mock.Anything,
					).
					Return(handle, nil)
			},
			assert: func(t *testing.T, informer *secrets.SecretInformer[string], err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, informer)
			},
		},
		"creates informer with lazy mode": {
			opts: []secrets.InformerOptions[string]{
				{
					Converter: func(secret secrets.Secret) (string, error) {
						return secret.Selector(), nil
					},
					ResolveMode: secrets.ResolveLazy,
				},
			},
			setup: func(t *testing.T, resolver *mocks.ResolverMock, handle *mocks.SecretHandleMock) {
				t.Helper()

				resolver.EXPECT().
					Secret(
						mock.Anything,
						secrets.Reference{Source: "src", Selector: "selector"},
						mock.Anything,
					).
					Return(handle, nil)
			},
			assert: func(t *testing.T, informer *secrets.SecretInformer[string], err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, informer)
			},
		},
		"returns resolver error": {
			opts: []secrets.InformerOptions[string]{
				{
					Converter: func(secret secrets.Secret) (string, error) {
						return secret.Selector(), nil
					},
					ResolveMode: secrets.ResolveEager,
				},
			},
			setup: func(t *testing.T, resolver *mocks.ResolverMock, _ *mocks.SecretHandleMock) {
				t.Helper()

				resolver.EXPECT().
					Secret(
						mock.Anything,
						secrets.Reference{Source: "src", Selector: "selector"},
						mock.Anything,
					).
					Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, informer *secrets.SecretInformer[string], err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.Nil(t, informer)
			},
		},
		"returns error if more than one option is provided": {
			opts: []secrets.InformerOptions[string]{
				{},
				{},
			},
			setup: func(t *testing.T, _ *mocks.ResolverMock, _ *mocks.SecretHandleMock) {
				t.Helper()
			},
			assert: func(t *testing.T, informer *secrets.SecretInformer[string], err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, secrets.ErrTooManyInformerOptions)
				require.Nil(t, informer)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			resolver := mocks.NewResolverMock(t)
			handle := mocks.NewSecretHandleMock(t)

			tc.setup(t, resolver, handle)

			informer, err := secrets.NewSecretInformer(
				context.Background(),
				resolver,
				secrets.Reference{Source: "src", Selector: "selector"},
				tc.opts...,
			)

			tc.assert(t, informer, err)
		})
	}
}

func TestSecretInformerGet(t *testing.T) {
	t.Parallel()

	secret := types.NewStringSecret("selector", "value")

	for uc, tc := range map[string]struct {
		setup     func(t *testing.T, handle *mocks.SecretHandleMock)
		opts      []secrets.InformerOptions[string]
		wantValue string
		wantOK    bool
		assert    func(t *testing.T, converterCalls int)
	}{
		"returns converted secret": {
			setup: func(t *testing.T, handle *mocks.SecretHandleMock) {
				t.Helper()

				handle.EXPECT().
					Get(mock.Anything).
					Return(secret, true)
			},
			opts: []secrets.InformerOptions[string]{
				{
					Converter: func(secret secrets.Secret) (string, error) {
						return secret.Selector(), nil
					},
				},
			},
			wantValue: "selector",
			wantOK:    true,
			assert: func(t *testing.T, converterCalls int) {
				t.Helper()

				require.Equal(t, 1, converterCalls)
			},
		},
		"returns false if handle has no value": {
			setup: func(t *testing.T, handle *mocks.SecretHandleMock) {
				t.Helper()

				handle.EXPECT().
					Get(mock.Anything).
					Return(nil, false)
			},
			opts: []secrets.InformerOptions[string]{
				{
					Converter: func(secret secrets.Secret) (string, error) {
						return secret.Selector(), nil
					},
				},
			},
			wantOK: false,
			assert: func(t *testing.T, converterCalls int) {
				t.Helper()

				require.Zero(t, converterCalls)
			},
		},
		"returns false if conversion fails": {
			setup: func(t *testing.T, handle *mocks.SecretHandleMock) {
				t.Helper()

				handle.EXPECT().
					Get(mock.Anything).
					Return(secret, true)
			},
			opts: []secrets.InformerOptions[string]{
				{
					Converter: func(secrets.Secret) (string, error) {
						return "", assert.AnError
					},
				},
			},
			wantOK: false,
			assert: func(t *testing.T, converterCalls int) {
				t.Helper()

				require.Equal(t, 1, converterCalls)
			},
		},
		"returns false if identity converter cannot cast": {
			setup: func(t *testing.T, handle *mocks.SecretHandleMock) {
				t.Helper()

				handle.EXPECT().
					Get(mock.Anything).
					Return(secret, true)
			},
			wantOK: false,
			assert: func(t *testing.T, converterCalls int) {
				t.Helper()

				require.Zero(t, converterCalls)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			handle := mocks.NewSecretHandleMock(t)
			resolver := mocks.NewResolverMock(t)

			tc.setup(t, handle)

			resolver.EXPECT().
				Secret(
					mock.Anything,
					secrets.Reference{Source: "src", Selector: "selector"},
				).
				Return(handle, nil)

			converterCalls := 0

			opts := append([]secrets.InformerOptions[string]{}, tc.opts...)

			if len(opts) == 1 && opts[0].Converter != nil {
				converter := opts[0].Converter

				opts[0].Converter = func(secret secrets.Secret) (string, error) {
					converterCalls++

					return converter(secret)
				}
			}

			informer, err := secrets.NewSecretInformer(
				context.Background(),
				resolver,
				secrets.Reference{Source: "src", Selector: "selector"},
				opts...,
			)
			require.NoError(t, err)

			got, ok := informer.Get(context.Background())

			require.Equal(t, tc.wantOK, ok)
			require.Equal(t, tc.wantValue, got)

			tc.assert(t, converterCalls)
		})
	}
}

func TestSecretInformerGetUsesIdentityConverter(t *testing.T) {
	t.Parallel()

	secret := types.NewStringSecret("selector", "value")

	handle := mocks.NewSecretHandleMock(t)
	resolver := mocks.NewResolverMock(t)

	resolver.EXPECT().
		Secret(
			mock.Anything,
			secrets.Reference{Source: "src", Selector: "selector"},
		).
		Return(handle, nil)

	handle.EXPECT().
		Get(mock.Anything).
		Return(secret, true)

	informer, err := secrets.NewSecretInformer[secrets.Secret](
		context.Background(),
		resolver,
		secrets.Reference{Source: "src", Selector: "selector"},
	)
	require.NoError(t, err)

	got, ok := informer.Get(context.Background())

	require.True(t, ok)
	require.Equal(t, secret, got)
}

func TestSecretInformerRegistersOnUpdate(t *testing.T) {
	t.Parallel()

	secret := types.NewStringSecret("selector", "value")

	for uc, tc := range map[string]struct {
		setup     func(t *testing.T, handle *mocks.SecretHandleMock, cbErr *error, wrappedCallbackCalled *bool)
		converter secrets.SecretConverter[string]
		assert    func(t *testing.T, cbErr error, wrappedCallbackCalled bool, userCallbackCalled bool)
	}{
		"converts secret and calls callback": {
			setup: func(
				t *testing.T,
				handle *mocks.SecretHandleMock,
				cbErr *error,
				wrappedCallbackCalled *bool,
			) {
				t.Helper()

				handle.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Secret]) bool {
						*cbErr = cb(context.Background(), secret)
						*wrappedCallbackCalled = true

						return true
					}))
			},
			converter: func(secret secrets.Secret) (string, error) {
				return secret.Selector(), nil
			},
			assert: func(t *testing.T, cbErr error, wrappedCallbackCalled bool, userCallbackCalled bool) {
				t.Helper()

				require.True(t, wrappedCallbackCalled)
				require.True(t, userCallbackCalled)
				require.NoError(t, cbErr)
			},
		},
		"returns conversion error": {
			setup: func(
				t *testing.T,
				handle *mocks.SecretHandleMock,
				cbErr *error,
				wrappedCallbackCalled *bool,
			) {
				t.Helper()

				handle.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Secret]) bool {
						*cbErr = cb(context.Background(), secret)
						*wrappedCallbackCalled = true

						return true
					}))
			},
			converter: func(secrets.Secret) (string, error) {
				return "", assert.AnError
			},
			assert: func(t *testing.T, cbErr error, wrappedCallbackCalled bool, userCallbackCalled bool) {
				t.Helper()

				require.True(t, wrappedCallbackCalled)
				require.False(t, userCallbackCalled)
				require.Error(t, cbErr)
				require.ErrorIs(t, cbErr, secrets.ErrSecretConversionFailed)
				require.ErrorIs(t, cbErr, assert.AnError)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			handle := mocks.NewSecretHandleMock(t)
			resolver := mocks.NewResolverMock(t)

			resolver.EXPECT().
				Secret(
					mock.Anything,
					secrets.Reference{Source: "src", Selector: "selector"},
				).
				Return(handle, nil)

			var cbErr error

			wrappedCallbackCalled := false

			tc.setup(t, handle, &cbErr, &wrappedCallbackCalled)

			userCallbackCalled := false

			informer, err := secrets.NewSecretInformer(
				context.Background(),
				resolver,
				secrets.Reference{Source: "src", Selector: "selector"},
				secrets.InformerOptions[string]{
					Converter: tc.converter,
					OnUpdate: func(_ context.Context, got secrets.Secret, value string) error {
						userCallbackCalled = true

						require.Equal(t, secret, got)
						require.Equal(t, "selector", value)

						return nil
					},
				},
			)

			require.NoError(t, err)
			require.NotNil(t, informer)

			tc.assert(t, cbErr, wrappedCallbackCalled, userCallbackCalled)
		})
	}
}

func TestSecretInformerDoesNotRegisterNilOnUpdate(t *testing.T) {
	t.Parallel()

	resolver := mocks.NewResolverMock(t)
	handle := mocks.NewSecretHandleMock(t)

	resolver.EXPECT().
		Secret(
			mock.Anything,
			secrets.Reference{Source: "src", Selector: "selector"},
		).
		Return(handle, nil)

	informer, err := secrets.NewSecretInformer(
		context.Background(),
		resolver,
		secrets.Reference{Source: "src", Selector: "selector"},
		secrets.InformerOptions[string]{
			Converter: func(secret secrets.Secret) (string, error) {
				return secret.Selector(), nil
			},
		},
	)

	require.NoError(t, err)
	require.NotNil(t, informer)
}

func TestNewCredentialsInformer(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, resolver *mocks.ResolverMock, handle *mocks.CredentialsHandleMock)
		opts   []secrets.CredentialsInformerOptions[string]
		assert func(t *testing.T, informer *secrets.CredentialsInformer[string], err error)
	}{
		"creates informer without options": {
			setup: func(t *testing.T, resolver *mocks.ResolverMock, handle *mocks.CredentialsHandleMock) {
				t.Helper()

				resolver.EXPECT().
					Credentials(
						mock.Anything,
						secrets.Reference{Source: "src", Selector: "selector"},
					).
					Return(handle, nil)
			},
			assert: func(t *testing.T, informer *secrets.CredentialsInformer[string], err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, informer)
			},
		},
		"creates informer with eager mode": {
			opts: []secrets.CredentialsInformerOptions[string]{
				{
					Converter: func(credentials secrets.Credentials) (string, error) {
						return credentials.Selector(), nil
					},
					ResolveMode: secrets.ResolveEager,
				},
			},
			setup: func(t *testing.T, resolver *mocks.ResolverMock, handle *mocks.CredentialsHandleMock) {
				t.Helper()

				resolver.EXPECT().
					Credentials(
						mock.Anything,
						secrets.Reference{Source: "src", Selector: "selector"},
						mock.Anything,
					).
					Return(handle, nil)
			},
			assert: func(t *testing.T, informer *secrets.CredentialsInformer[string], err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, informer)
			},
		},
		"creates informer with lazy mode": {
			opts: []secrets.CredentialsInformerOptions[string]{
				{
					Converter: func(credentials secrets.Credentials) (string, error) {
						return credentials.Selector(), nil
					},
					ResolveMode: secrets.ResolveLazy,
				},
			},
			setup: func(t *testing.T, resolver *mocks.ResolverMock, handle *mocks.CredentialsHandleMock) {
				t.Helper()

				resolver.EXPECT().
					Credentials(
						mock.Anything,
						secrets.Reference{Source: "src", Selector: "selector"},
						mock.Anything,
					).
					Return(handle, nil)
			},
			assert: func(t *testing.T, informer *secrets.CredentialsInformer[string], err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, informer)
			},
		},
		"returns resolver error": {
			opts: []secrets.CredentialsInformerOptions[string]{
				{
					Converter: func(credentials secrets.Credentials) (string, error) {
						return credentials.Selector(), nil
					},
					ResolveMode: secrets.ResolveEager,
				},
			},
			setup: func(t *testing.T, resolver *mocks.ResolverMock, _ *mocks.CredentialsHandleMock) {
				t.Helper()

				resolver.EXPECT().
					Credentials(
						mock.Anything,
						secrets.Reference{Source: "src", Selector: "selector"},
						mock.Anything,
					).
					Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, informer *secrets.CredentialsInformer[string], err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.Nil(t, informer)
			},
		},
		"returns error if more than one option is provided": {
			opts: []secrets.CredentialsInformerOptions[string]{
				{},
				{},
			},
			setup: func(t *testing.T, _ *mocks.ResolverMock, _ *mocks.CredentialsHandleMock) {
				t.Helper()
			},
			assert: func(t *testing.T, informer *secrets.CredentialsInformer[string], err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, secrets.ErrTooManyInformerOptions)
				require.Nil(t, informer)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			resolver := mocks.NewResolverMock(t)
			handle := mocks.NewCredentialsHandleMock(t)

			tc.setup(t, resolver, handle)

			informer, err := secrets.NewCredentialsInformer(
				context.Background(),
				resolver,
				secrets.Reference{Source: "src", Selector: "selector"},
				tc.opts...,
			)

			tc.assert(t, informer, err)
		})
	}
}

func TestCredentialsInformerGet(t *testing.T) {
	t.Parallel()

	credentials := types.NewCredentials("selector", map[string]any{"client_id": "heimdall"})

	for uc, tc := range map[string]struct {
		setup     func(t *testing.T, handle *mocks.CredentialsHandleMock)
		opts      []secrets.CredentialsInformerOptions[string]
		wantValue string
		wantOK    bool
		assert    func(t *testing.T, converterCalls int)
	}{
		"returns converted credentials": {
			setup: func(t *testing.T, handle *mocks.CredentialsHandleMock) {
				t.Helper()

				handle.EXPECT().
					Get(mock.Anything).
					Return(credentials, true)
			},
			opts: []secrets.CredentialsInformerOptions[string]{
				{
					Converter: func(credentials secrets.Credentials) (string, error) {
						return credentials.Selector(), nil
					},
				},
			},
			wantValue: "selector",
			wantOK:    true,
			assert: func(t *testing.T, converterCalls int) {
				t.Helper()

				require.Equal(t, 1, converterCalls)
			},
		},
		"returns false if handle has no value": {
			setup: func(t *testing.T, handle *mocks.CredentialsHandleMock) {
				t.Helper()

				handle.EXPECT().
					Get(mock.Anything).
					Return(nil, false)
			},
			opts: []secrets.CredentialsInformerOptions[string]{
				{
					Converter: func(credentials secrets.Credentials) (string, error) {
						return credentials.Selector(), nil
					},
				},
			},
			wantOK: false,
			assert: func(t *testing.T, converterCalls int) {
				t.Helper()

				require.Zero(t, converterCalls)
			},
		},
		"returns false if conversion fails": {
			setup: func(t *testing.T, handle *mocks.CredentialsHandleMock) {
				t.Helper()

				handle.EXPECT().
					Get(mock.Anything).
					Return(credentials, true)
			},
			opts: []secrets.CredentialsInformerOptions[string]{
				{
					Converter: func(secrets.Credentials) (string, error) {
						return "", assert.AnError
					},
				},
			},
			wantOK: false,
			assert: func(t *testing.T, converterCalls int) {
				t.Helper()

				require.Equal(t, 1, converterCalls)
			},
		},
		"returns false if identity converter cannot cast": {
			setup: func(t *testing.T, handle *mocks.CredentialsHandleMock) {
				t.Helper()

				handle.EXPECT().
					Get(mock.Anything).
					Return(credentials, true)
			},
			wantOK: false,
			assert: func(t *testing.T, converterCalls int) {
				t.Helper()

				require.Zero(t, converterCalls)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			handle := mocks.NewCredentialsHandleMock(t)
			resolver := mocks.NewResolverMock(t)

			tc.setup(t, handle)

			resolver.EXPECT().
				Credentials(
					mock.Anything,
					secrets.Reference{Source: "src", Selector: "selector"},
				).
				Return(handle, nil)

			converterCalls := 0

			opts := append([]secrets.CredentialsInformerOptions[string]{}, tc.opts...)

			if len(opts) == 1 && opts[0].Converter != nil {
				converter := opts[0].Converter

				opts[0].Converter = func(credentials secrets.Credentials) (string, error) {
					converterCalls++

					return converter(credentials)
				}
			}

			informer, err := secrets.NewCredentialsInformer(
				context.Background(),
				resolver,
				secrets.Reference{Source: "src", Selector: "selector"},
				opts...,
			)
			require.NoError(t, err)

			got, ok := informer.Get(context.Background())

			require.Equal(t, tc.wantOK, ok)
			require.Equal(t, tc.wantValue, got)

			tc.assert(t, converterCalls)
		})
	}
}

func TestCredentialsInformerGetUsesIdentityConverter(t *testing.T) {
	t.Parallel()

	credentials := types.NewCredentials("selector", map[string]any{"client_id": "heimdall"})

	handle := mocks.NewCredentialsHandleMock(t)
	resolver := mocks.NewResolverMock(t)

	resolver.EXPECT().
		Credentials(
			mock.Anything,
			secrets.Reference{Source: "src", Selector: "selector"},
		).
		Return(handle, nil)

	handle.EXPECT().
		Get(mock.Anything).
		Return(credentials, true)

	informer, err := secrets.NewCredentialsInformer[secrets.Credentials](
		context.Background(),
		resolver,
		secrets.Reference{Source: "src", Selector: "selector"},
	)
	require.NoError(t, err)

	got, ok := informer.Get(context.Background())

	require.True(t, ok)
	require.Equal(t, credentials, got)
}

func TestCredentialsInformerRegistersOnUpdate(t *testing.T) {
	t.Parallel()

	credentials := types.NewCredentials("selector", map[string]any{"client_id": "heimdall"})

	for uc, tc := range map[string]struct {
		setup     func(t *testing.T, handle *mocks.CredentialsHandleMock, cbErr *error, wrappedCallbackCalled *bool)
		converter secrets.CredentialsConverter[string]
		assert    func(t *testing.T, cbErr error, wrappedCallbackCalled bool, userCallbackCalled bool)
	}{
		"converts credentials and calls callback": {
			setup: func(
				t *testing.T,
				handle *mocks.CredentialsHandleMock,
				cbErr *error,
				wrappedCallbackCalled *bool,
			) {
				t.Helper()

				handle.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Credentials]) bool {
						*cbErr = cb(context.Background(), credentials)
						*wrappedCallbackCalled = true

						return true
					}))
			},
			converter: func(credentials secrets.Credentials) (string, error) {
				return credentials.Selector(), nil
			},
			assert: func(t *testing.T, cbErr error, wrappedCallbackCalled bool, userCallbackCalled bool) {
				t.Helper()

				require.True(t, wrappedCallbackCalled)
				require.True(t, userCallbackCalled)
				require.NoError(t, cbErr)
			},
		},
		"returns conversion error": {
			setup: func(
				t *testing.T,
				handle *mocks.CredentialsHandleMock,
				cbErr *error,
				wrappedCallbackCalled *bool,
			) {
				t.Helper()

				handle.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Credentials]) bool {
						*cbErr = cb(context.Background(), credentials)
						*wrappedCallbackCalled = true

						return true
					}))
			},
			converter: func(secrets.Credentials) (string, error) {
				return "", assert.AnError
			},
			assert: func(t *testing.T, cbErr error, wrappedCallbackCalled bool, userCallbackCalled bool) {
				t.Helper()

				require.True(t, wrappedCallbackCalled)
				require.False(t, userCallbackCalled)
				require.Error(t, cbErr)
				require.ErrorIs(t, cbErr, assert.AnError)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			handle := mocks.NewCredentialsHandleMock(t)
			resolver := mocks.NewResolverMock(t)

			resolver.EXPECT().
				Credentials(
					mock.Anything,
					secrets.Reference{Source: "src", Selector: "selector"},
				).
				Return(handle, nil)

			var cbErr error

			wrappedCallbackCalled := false

			tc.setup(t, handle, &cbErr, &wrappedCallbackCalled)

			userCallbackCalled := false

			informer, err := secrets.NewCredentialsInformer(
				context.Background(),
				resolver,
				secrets.Reference{Source: "src", Selector: "selector"},
				secrets.CredentialsInformerOptions[string]{
					Converter: tc.converter,
					OnUpdate: func(_ context.Context, got secrets.Credentials, value string) error {
						userCallbackCalled = true

						require.Equal(t, credentials, got)
						require.Equal(t, "selector", value)

						return nil
					},
				},
			)

			require.NoError(t, err)
			require.NotNil(t, informer)

			tc.assert(t, cbErr, wrappedCallbackCalled, userCallbackCalled)
		})
	}
}

func TestCredentialsInformerDoesNotRegisterNilOnUpdate(t *testing.T) {
	t.Parallel()

	resolver := mocks.NewResolverMock(t)
	handle := mocks.NewCredentialsHandleMock(t)

	resolver.EXPECT().
		Credentials(
			mock.Anything,
			secrets.Reference{Source: "src", Selector: "selector"},
		).
		Return(handle, nil)

	informer, err := secrets.NewCredentialsInformer(
		context.Background(),
		resolver,
		secrets.Reference{Source: "src", Selector: "selector"},
		secrets.CredentialsInformerOptions[string]{
			Converter: func(credentials secrets.Credentials) (string, error) {
				return credentials.Selector(), nil
			},
		},
	)

	require.NoError(t, err)
	require.NotNil(t, informer)
}

func TestNewCertificateBundleInformer(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, resolver *mocks.ResolverMock, handle *mocks.CertificateBundleHandleMock)
		opts   []secrets.CertificateBundleInformerOptions
		assert func(t *testing.T, informer *secrets.CertificateBundleInformer, err error)
	}{
		"creates informer without options": {
			setup: func(t *testing.T, resolver *mocks.ResolverMock, handle *mocks.CertificateBundleHandleMock) {
				t.Helper()

				resolver.EXPECT().
					CertificateBundle(
						mock.Anything,
						secrets.Reference{Source: "src", Selector: "selector"},
					).
					Return(handle, nil)
			},
			assert: func(t *testing.T, informer *secrets.CertificateBundleInformer, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, informer)
			},
		},
		"creates informer with eager mode": {
			opts: []secrets.CertificateBundleInformerOptions{
				{
					ResolveMode: secrets.ResolveEager,
				},
			},
			setup: func(t *testing.T, resolver *mocks.ResolverMock, handle *mocks.CertificateBundleHandleMock) {
				t.Helper()

				resolver.EXPECT().
					CertificateBundle(
						mock.Anything,
						secrets.Reference{Source: "src", Selector: "selector"},
						mock.Anything,
					).
					Return(handle, nil)
			},
			assert: func(t *testing.T, informer *secrets.CertificateBundleInformer, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, informer)
			},
		},
		"creates informer with lazy mode": {
			opts: []secrets.CertificateBundleInformerOptions{
				{
					ResolveMode: secrets.ResolveLazy,
				},
			},
			setup: func(t *testing.T, resolver *mocks.ResolverMock, handle *mocks.CertificateBundleHandleMock) {
				t.Helper()

				resolver.EXPECT().
					CertificateBundle(
						mock.Anything,
						secrets.Reference{Source: "src", Selector: "selector"},
						mock.Anything,
					).
					Return(handle, nil)
			},
			assert: func(t *testing.T, informer *secrets.CertificateBundleInformer, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, informer)
			},
		},
		"returns resolver error": {
			opts: []secrets.CertificateBundleInformerOptions{
				{
					ResolveMode: secrets.ResolveEager,
				},
			},
			setup: func(t *testing.T, resolver *mocks.ResolverMock, _ *mocks.CertificateBundleHandleMock) {
				t.Helper()

				resolver.EXPECT().
					CertificateBundle(
						mock.Anything,
						secrets.Reference{Source: "src", Selector: "selector"},
						mock.Anything,
					).
					Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, informer *secrets.CertificateBundleInformer, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.Nil(t, informer)
			},
		},
		"returns error if more than one option is provided": {
			opts: []secrets.CertificateBundleInformerOptions{
				{},
				{},
			},
			setup: func(t *testing.T, _ *mocks.ResolverMock, _ *mocks.CertificateBundleHandleMock) {
				t.Helper()
			},
			assert: func(t *testing.T, informer *secrets.CertificateBundleInformer, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, secrets.ErrTooManyInformerOptions)
				require.Nil(t, informer)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			resolver := mocks.NewResolverMock(t)
			handle := mocks.NewCertificateBundleHandleMock(t)

			tc.setup(t, resolver, handle)

			informer, err := secrets.NewCertificateBundleInformer(
				context.Background(),
				resolver,
				secrets.Reference{Source: "src", Selector: "selector"},
				tc.opts...,
			)

			tc.assert(t, informer, err)
		})
	}
}

func TestCertificateBundleInformerGet(t *testing.T) {
	t.Parallel()

	bundle := types.NewCertificateBundle("selector", nil)

	for uc, tc := range map[string]struct {
		setup   func(t *testing.T, handle *mocks.CertificateBundleHandleMock)
		wantOK  bool
		wantNil bool
	}{
		"returns cert pool": {
			setup: func(t *testing.T, handle *mocks.CertificateBundleHandleMock) {
				t.Helper()

				handle.EXPECT().
					Get(mock.Anything).
					Return(bundle, true)
			},
			wantOK: true,
		},
		"returns false if handle has no value": {
			setup: func(t *testing.T, handle *mocks.CertificateBundleHandleMock) {
				t.Helper()

				handle.EXPECT().
					Get(mock.Anything).
					Return(nil, false)
			},
			wantOK:  false,
			wantNil: true,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			handle := mocks.NewCertificateBundleHandleMock(t)
			resolver := mocks.NewResolverMock(t)

			tc.setup(t, handle)

			resolver.EXPECT().
				CertificateBundle(
					mock.Anything,
					secrets.Reference{Source: "src", Selector: "selector"},
				).
				Return(handle, nil)

			informer, err := secrets.NewCertificateBundleInformer(
				context.Background(),
				resolver,
				secrets.Reference{Source: "src", Selector: "selector"},
			)
			require.NoError(t, err)

			got, ok := informer.Get(context.Background())

			require.Equal(t, tc.wantOK, ok)

			if tc.wantNil {
				require.Nil(t, got)

				return
			}

			require.NotNil(t, got)
		})
	}
}

func TestCertificateBundleInformerRegistersOnUpdate(t *testing.T) {
	t.Parallel()

	bundle := types.NewCertificateBundle("selector", nil)

	handle := mocks.NewCertificateBundleHandleMock(t)
	resolver := mocks.NewResolverMock(t)

	resolver.EXPECT().
		CertificateBundle(
			mock.Anything,
			secrets.Reference{Source: "src", Selector: "selector"},
		).
		Return(handle, nil)

	var cbErr error

	wrappedCallbackCalled := false

	handle.EXPECT().
		OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.CertificateBundle]) bool {
			cbErr = cb(context.Background(), bundle)
			wrappedCallbackCalled = true

			return true
		}))

	userCallbackCalled := false

	informer, err := secrets.NewCertificateBundleInformer(
		context.Background(),
		resolver,
		secrets.Reference{Source: "src", Selector: "selector"},
		secrets.CertificateBundleInformerOptions{
			OnUpdate: func(_ context.Context, got secrets.CertificateBundle, pool *x509.CertPool) error {
				userCallbackCalled = true

				require.Equal(t, bundle, got)
				require.NotNil(t, pool)

				return nil
			},
		},
	)

	require.NoError(t, err)
	require.NotNil(t, informer)
	require.True(t, wrappedCallbackCalled)
	require.True(t, userCallbackCalled)
	require.NoError(t, cbErr)
}

func TestCertificateBundleInformerDoesNotRegisterNilOnUpdate(t *testing.T) {
	t.Parallel()

	resolver := mocks.NewResolverMock(t)
	handle := mocks.NewCertificateBundleHandleMock(t)

	resolver.EXPECT().
		CertificateBundle(
			mock.Anything,
			secrets.Reference{Source: "src", Selector: "selector"},
		).
		Return(handle, nil)

	informer, err := secrets.NewCertificateBundleInformer(
		context.Background(),
		resolver,
		secrets.Reference{Source: "src", Selector: "selector"},
	)

	require.NoError(t, err)
	require.NotNil(t, informer)
}
