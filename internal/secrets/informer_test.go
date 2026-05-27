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
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/secrets/types"
)

func TestNewSecretInformer(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, resolver *testResolver, handle *testHandle[Secret])
		opts   []SecretInformerOption[string]
		assert func(
			t *testing.T,
			informer *SecretInformer[string],
			err error,
			resolver *testResolver,
			handle *testHandle[Secret],
		)
	}{
		"creates informer": {
			opts: []SecretInformerOption[string]{
				WithConverter(func(secret Secret) (string, error) {
					return secret.Selector(), nil
				}),
			},
			setup: func(t *testing.T, resolver *testResolver, handle *testHandle[Secret]) {
				t.Helper()

				resolver.secretHandle = handle
			},
			assert: func(
				t *testing.T,
				informer *SecretInformer[string],
				err error,
				resolver *testResolver,
				handle *testHandle[Secret],
			) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, informer)
				require.Equal(t, Reference{Source: "src", Selector: "selector"}, resolver.secretRef)
				require.Len(t, handle.readiness, 1)
				require.NotNil(t, handle.callback)
			},
		},
		"returns resolver error": {
			setup: func(t *testing.T, resolver *testResolver, _ *testHandle[Secret]) {
				t.Helper()

				resolver.secretErr = assert.AnError
			},
			assert: func(
				t *testing.T,
				informer *SecretInformer[string],
				err error,
				_ *testResolver,
				_ *testHandle[Secret],
			) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.Nil(t, informer)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			resolver := &testResolver{}
			handle := newTestHandle[Secret]()

			tc.setup(t, resolver, handle)

			informer, err := NewSecretInformer(
				t.Context(),
				resolver,
				Reference{Source: "src", Selector: "selector"},
				tc.opts...,
			)

			tc.assert(t, informer, err, resolver, handle)
		})
	}
}

func TestSecretInformerGet(t *testing.T) {
	t.Parallel()

	secret := types.NewStringSecret("selector", "value")

	for uc, tc := range map[string]struct {
		opts               []SecretInformerOption[string]
		emit               func(t *testing.T, handle *testHandle[Secret]) error
		wantValue          string
		wantOK             bool
		wantConverterCalls int
		wantErr            error
	}{
		"returns false before first successful update": {
			opts: []SecretInformerOption[string]{
				WithConverter(func(secret Secret) (string, error) {
					return secret.Selector(), nil
				}),
			},
			wantOK: false,
		},
		"returns converted last good value": {
			opts: []SecretInformerOption[string]{
				WithConverter(func(secret Secret) (string, error) {
					return secret.Selector(), nil
				}),
			},
			emit: func(t *testing.T, handle *testHandle[Secret]) error {
				t.Helper()

				return handle.emit(t.Context(), secret)
			},
			wantValue:          "selector",
			wantOK:             true,
			wantConverterCalls: 1,
		},
		"keeps last good value after failed conversion": {
			opts: []SecretInformerOption[string]{
				WithConverter(func(secret Secret) (string, error) {
					if secret.Selector() == "bad" {
						return "", assert.AnError
					}

					return secret.Selector(), nil
				}),
			},
			emit: func(t *testing.T, handle *testHandle[Secret]) error {
				t.Helper()

				if err := handle.emit(t.Context(), secret); err != nil {
					return err
				}

				return handle.emit(t.Context(), types.NewStringSecret("bad", "value"))
			},
			wantValue:          "selector",
			wantOK:             true,
			wantConverterCalls: 2,
			wantErr:            assert.AnError,
		},
		"identity converter cannot cast": {
			emit: func(t *testing.T, handle *testHandle[Secret]) error {
				t.Helper()

				return handle.emit(t.Context(), secret)
			},
			wantOK:  false,
			wantErr: ErrSecretConversionFailed,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			handle := newTestHandle[Secret]()
			resolver := &testResolver{secretHandle: handle}

			converterCalls := 0
			opts := wrapSecretConverters(tc.opts, &converterCalls)

			informer, err := NewSecretInformer(
				t.Context(),
				resolver,
				Reference{Source: "src", Selector: "selector"},
				opts...,
			)
			require.NoError(t, err)

			if tc.emit != nil {
				err = tc.emit(t, handle)
				if tc.wantErr != nil {
					require.Error(t, err)
					require.ErrorIs(t, err, tc.wantErr)
				} else {
					require.NoError(t, err)
				}
			}

			got, ok := informer.Get()

			require.Equal(t, tc.wantOK, ok)
			require.Equal(t, tc.wantValue, got)
			require.Equal(t, tc.wantConverterCalls, converterCalls)
		})
	}
}

func TestSecretInformerGetUsesIdentityConverter(t *testing.T) {
	t.Parallel()

	secret := types.NewStringSecret("selector", "value")
	handle := newTestHandle[Secret]()
	resolver := &testResolver{secretHandle: handle}

	informer, err := NewSecretInformer[Secret](
		t.Context(),
		resolver,
		Reference{Source: "src", Selector: "selector"},
	)
	require.NoError(t, err)

	require.NoError(t, handle.emit(t.Context(), secret))

	got, ok := informer.Get()

	require.True(t, ok)
	require.Equal(t, secret, got)
}

func TestSecretInformerAwaitReady(t *testing.T) {
	t.Parallel()

	secret := types.NewStringSecret("selector", "value")

	for uc, tc := range map[string]struct {
		converter func(t *testing.T, secret Secret) (string, error)
		assert    func(t *testing.T, err error)
	}{
		"returns nil after successful conversion": {
			converter: func(t *testing.T, secret Secret) (string, error) {
				t.Helper()

				return secret.Selector(), nil
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"returns last conversion error on context cancellation": {
			converter: func(t *testing.T, _ Secret) (string, error) {
				t.Helper()

				return "", assert.AnError
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

			handle := newTestHandle[Secret]()
			resolver := &testResolver{secretHandle: handle}

			_, err := NewSecretInformer(
				t.Context(),
				resolver,
				Reference{Source: "src", Selector: "selector"},
				WithConverter(func(secret Secret) (string, error) {
					return tc.converter(t, secret)
				}),
			)
			require.NoError(t, err)

			_ = handle.emit(t.Context(), secret)

			ctx, cancel := context.WithCancel(t.Context())
			cancel()

			tc.assert(t, handle.awaitReady(ctx))
		})
	}
}

func TestSecretInformerRegistersOnUpdateCallback(t *testing.T) {
	t.Parallel()

	secret := types.NewStringSecret("selector", "value")

	for uc, tc := range map[string]struct {
		converter func(t *testing.T, secret Secret) (string, error)
		callback  func(t *testing.T, ctx context.Context, secret Secret, value string) error
		assert    func(t *testing.T, err error, userCallbackCalled bool, informer *SecretInformer[string])
	}{
		"calls user callback with converted value": {
			converter: func(t *testing.T, secret Secret) (string, error) {
				t.Helper()

				return secret.Selector(), nil
			},
			callback: func(t *testing.T, _ context.Context, got Secret, value string) error {
				t.Helper()

				require.Equal(t, secret, got)
				require.Equal(t, "selector", value)

				return nil
			},
			assert: func(t *testing.T, err error, userCallbackCalled bool, _ *SecretInformer[string]) {
				t.Helper()

				require.NoError(t, err)
				require.True(t, userCallbackCalled)
			},
		},
		"returns user callback error but keeps converted value": {
			converter: func(t *testing.T, secret Secret) (string, error) {
				t.Helper()

				return secret.Selector(), nil
			},
			callback: func(t *testing.T, _ context.Context, _ Secret, _ string) error {
				t.Helper()

				return assert.AnError
			},
			assert: func(t *testing.T, err error, userCallbackCalled bool, informer *SecretInformer[string]) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.True(t, userCallbackCalled)

				value, ok := informer.Get()
				require.True(t, ok)
				require.Equal(t, "selector", value)
			},
		},
		"returns conversion error and does not call user callback": {
			converter: func(t *testing.T, _ Secret) (string, error) {
				t.Helper()

				return "", assert.AnError
			},
			callback: func(t *testing.T, _ context.Context, _ Secret, _ string) error {
				t.Helper()

				return nil
			},
			assert: func(t *testing.T, err error, userCallbackCalled bool, informer *SecretInformer[string]) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.False(t, userCallbackCalled)

				_, ok := informer.Get()
				require.False(t, ok)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			handle := newTestHandle[Secret]()
			resolver := &testResolver{secretHandle: handle}

			userCallbackCalled := false

			informer, err := NewSecretInformer(
				t.Context(),
				resolver,
				Reference{Source: "src", Selector: "selector"},
				WithConverter(func(secret Secret) (string, error) {
					return tc.converter(t, secret)
				}),
				WithUpdateCallback(func(ctx context.Context, got Secret, value string) error {
					userCallbackCalled = true

					return tc.callback(t, ctx, got, value)
				}),
			)
			require.NoError(t, err)

			err = handle.emit(t.Context(), secret)

			tc.assert(t, err, userCallbackCalled, informer)
		})
	}
}

func TestNewCredentialsInformer(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, resolver *testResolver, handle *testHandle[Credentials])
		opts   []CredentialsInformerOption[string]
		assert func(
			t *testing.T,
			informer *CredentialsInformer[string],
			err error,
			resolver *testResolver,
			handle *testHandle[Credentials],
		)
	}{
		"creates informer": {
			opts: []CredentialsInformerOption[string]{
				WithConverter(func(credentials Credentials) (string, error) {
					return credentials.Selector(), nil
				}),
			},
			setup: func(t *testing.T, resolver *testResolver, handle *testHandle[Credentials]) {
				t.Helper()

				resolver.credentialsHandle = handle
			},
			assert: func(
				t *testing.T,
				informer *CredentialsInformer[string],
				err error,
				resolver *testResolver,
				handle *testHandle[Credentials],
			) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, informer)
				require.Equal(t, Reference{Source: "src", Selector: "selector"}, resolver.credentialsRef)
				require.Len(t, handle.readiness, 1)
				require.NotNil(t, handle.callback)
			},
		},
		"returns resolver error": {
			setup: func(t *testing.T, resolver *testResolver, _ *testHandle[Credentials]) {
				t.Helper()

				resolver.credentialsErr = assert.AnError
			},
			assert: func(
				t *testing.T,
				informer *CredentialsInformer[string],
				err error,
				_ *testResolver,
				_ *testHandle[Credentials],
			) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.Nil(t, informer)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			resolver := &testResolver{}
			handle := newTestHandle[Credentials]()

			tc.setup(t, resolver, handle)

			informer, err := NewCredentialsInformer(
				t.Context(),
				resolver,
				Reference{Source: "src", Selector: "selector"},
				tc.opts...,
			)

			tc.assert(t, informer, err, resolver, handle)
		})
	}
}

func TestCredentialsInformerGet(t *testing.T) {
	t.Parallel()

	credentials := types.NewCredentials("selector", map[string]any{"client_id": "heimdall"})

	for uc, tc := range map[string]struct {
		opts               []CredentialsInformerOption[string]
		emit               func(t *testing.T, handle *testHandle[Credentials]) error
		wantValue          string
		wantOK             bool
		wantConverterCalls int
		wantErr            error
	}{
		"returns false before first successful update": {
			opts: []CredentialsInformerOption[string]{
				WithConverter(func(credentials Credentials) (string, error) {
					return credentials.Selector(), nil
				}),
			},
			wantOK: false,
		},
		"returns converted last good value": {
			opts: []CredentialsInformerOption[string]{
				WithConverter(func(credentials Credentials) (string, error) {
					return credentials.Selector(), nil
				}),
			},
			emit: func(t *testing.T, handle *testHandle[Credentials]) error {
				t.Helper()

				return handle.emit(t.Context(), credentials)
			},
			wantValue:          "selector",
			wantOK:             true,
			wantConverterCalls: 1,
		},
		"keeps last good value after failed conversion": {
			opts: []CredentialsInformerOption[string]{
				WithConverter(func(credentials Credentials) (string, error) {
					if credentials.Selector() == "bad" {
						return "", assert.AnError
					}

					return credentials.Selector(), nil
				}),
			},
			emit: func(t *testing.T, handle *testHandle[Credentials]) error {
				t.Helper()

				if err := handle.emit(t.Context(), credentials); err != nil {
					return err
				}

				return handle.emit(
					t.Context(),
					types.NewCredentials("bad", map[string]any{"client_id": "heimdall"}),
				)
			},
			wantValue:          "selector",
			wantOK:             true,
			wantConverterCalls: 2,
			wantErr:            assert.AnError,
		},
		"identity converter cannot cast": {
			emit: func(t *testing.T, handle *testHandle[Credentials]) error {
				t.Helper()

				return handle.emit(t.Context(), credentials)
			},
			wantOK:  false,
			wantErr: ErrSecretConversionFailed,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			handle := newTestHandle[Credentials]()
			resolver := &testResolver{credentialsHandle: handle}

			converterCalls := 0
			opts := wrapCredentialsConverters(tc.opts, &converterCalls)

			informer, err := NewCredentialsInformer(
				t.Context(),
				resolver,
				Reference{Source: "src", Selector: "selector"},
				opts...,
			)
			require.NoError(t, err)

			if tc.emit != nil {
				err = tc.emit(t, handle)
				if tc.wantErr != nil {
					require.Error(t, err)
					require.ErrorIs(t, err, tc.wantErr)
				} else {
					require.NoError(t, err)
				}
			}

			got, ok := informer.Get()

			require.Equal(t, tc.wantOK, ok)
			require.Equal(t, tc.wantValue, got)
			require.Equal(t, tc.wantConverterCalls, converterCalls)
		})
	}
}

func TestCredentialsInformerGetUsesIdentityConverter(t *testing.T) {
	t.Parallel()

	credentials := types.NewCredentials("selector", map[string]any{"client_id": "heimdall"})
	handle := newTestHandle[Credentials]()
	resolver := &testResolver{credentialsHandle: handle}

	informer, err := NewCredentialsInformer[Credentials](
		t.Context(),
		resolver,
		Reference{Source: "src", Selector: "selector"},
	)
	require.NoError(t, err)

	require.NoError(t, handle.emit(t.Context(), credentials))

	got, ok := informer.Get()

	require.True(t, ok)
	require.Equal(t, credentials, got)
}

func TestCredentialsInformerAwaitReady(t *testing.T) {
	t.Parallel()

	credentials := types.NewCredentials("selector", map[string]any{"client_id": "heimdall"})

	for uc, tc := range map[string]struct {
		converter func(t *testing.T, credentials Credentials) (string, error)
		assert    func(t *testing.T, err error)
	}{
		"returns nil after successful conversion": {
			converter: func(t *testing.T, credentials Credentials) (string, error) {
				t.Helper()

				return credentials.Selector(), nil
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"returns last conversion error on context cancellation": {
			converter: func(t *testing.T, _ Credentials) (string, error) {
				t.Helper()

				return "", assert.AnError
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

			handle := newTestHandle[Credentials]()
			resolver := &testResolver{credentialsHandle: handle}

			_, err := NewCredentialsInformer(
				t.Context(),
				resolver,
				Reference{Source: "src", Selector: "selector"},
				WithConverter(func(credentials Credentials) (string, error) {
					return tc.converter(t, credentials)
				}),
			)
			require.NoError(t, err)

			_ = handle.emit(t.Context(), credentials)

			ctx, cancel := context.WithCancel(t.Context())
			cancel()

			tc.assert(t, handle.awaitReady(ctx))
		})
	}
}

func TestCredentialsInformerRegistersOnUpdateCallback(t *testing.T) {
	t.Parallel()

	credentials := types.NewCredentials("selector", map[string]any{"client_id": "heimdall"})
	handle := newTestHandle[Credentials]()
	resolver := &testResolver{credentialsHandle: handle}

	userCallbackCalled := false

	informer, err := NewCredentialsInformer(
		t.Context(),
		resolver,
		Reference{Source: "src", Selector: "selector"},
		WithConverter(func(credentials Credentials) (string, error) {
			return credentials.Selector(), nil
		}),
		WithUpdateCallback(func(_ context.Context, got Credentials, value string) error {
			userCallbackCalled = true

			require.Equal(t, credentials, got)
			require.Equal(t, "selector", value)

			return nil
		}),
	)

	require.NoError(t, err)
	require.NotNil(t, informer)

	require.NoError(t, handle.emit(t.Context(), credentials))
	require.True(t, userCallbackCalled)
}

func TestNewCertificateBundleInformer(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, resolver *testResolver, handle *testHandle[CertificateBundle])
		opts   []CertificateBundleInformerOption[string]
		assert func(
			t *testing.T,
			informer *CertificateBundleInformer[string],
			err error,
			resolver *testResolver,
			handle *testHandle[CertificateBundle],
		)
	}{
		"creates informer": {
			opts: []CertificateBundleInformerOption[string]{
				WithConverter(func(bundle CertificateBundle) (string, error) {
					return bundle.Selector(), nil
				}),
			},
			setup: func(t *testing.T, resolver *testResolver, handle *testHandle[CertificateBundle]) {
				t.Helper()

				resolver.certificateBundleHandle = handle
			},
			assert: func(
				t *testing.T,
				informer *CertificateBundleInformer[string],
				err error,
				resolver *testResolver,
				handle *testHandle[CertificateBundle],
			) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, informer)
				require.Equal(t, Reference{Source: "src", Selector: "selector"}, resolver.certificateBundleRef)
				require.Len(t, handle.readiness, 1)
				require.NotNil(t, handle.callback)
			},
		},
		"returns resolver error": {
			setup: func(t *testing.T, resolver *testResolver, _ *testHandle[CertificateBundle]) {
				t.Helper()

				resolver.certificateBundleErr = assert.AnError
			},
			assert: func(
				t *testing.T,
				informer *CertificateBundleInformer[string],
				err error,
				_ *testResolver,
				_ *testHandle[CertificateBundle],
			) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.Nil(t, informer)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			resolver := &testResolver{}
			handle := newTestHandle[CertificateBundle]()

			tc.setup(t, resolver, handle)

			informer, err := NewCertificateBundleInformer(
				t.Context(),
				resolver,
				Reference{Source: "src", Selector: "selector"},
				tc.opts...,
			)

			tc.assert(t, informer, err, resolver, handle)
		})
	}
}

func TestCertificateBundleInformerGet(t *testing.T) {
	t.Parallel()

	certificate := &x509.Certificate{}
	bundle := types.NewCertificateBundle("selector", []*x509.Certificate{certificate})

	for uc, tc := range map[string]struct {
		opts               []CertificateBundleInformerOption[string]
		emit               func(t *testing.T, handle *testHandle[CertificateBundle]) error
		wantValue          string
		wantOK             bool
		wantConverterCalls int
		wantErr            error
	}{
		"returns false before first successful update": {
			opts: []CertificateBundleInformerOption[string]{
				WithConverter(func(bundle CertificateBundle) (string, error) {
					return bundle.Selector(), nil
				}),
			},
			wantOK: false,
		},
		"returns converted last good value": {
			opts: []CertificateBundleInformerOption[string]{
				WithConverter(func(bundle CertificateBundle) (string, error) {
					return bundle.Selector(), nil
				}),
			},
			emit: func(t *testing.T, handle *testHandle[CertificateBundle]) error {
				t.Helper()

				return handle.emit(t.Context(), bundle)
			},
			wantValue:          "selector",
			wantOK:             true,
			wantConverterCalls: 1,
		},
		"keeps last good value after failed conversion": {
			opts: []CertificateBundleInformerOption[string]{
				WithConverter(func(bundle CertificateBundle) (string, error) {
					if bundle.Selector() == "bad" {
						return "", assert.AnError
					}

					return bundle.Selector(), nil
				}),
			},
			emit: func(t *testing.T, handle *testHandle[CertificateBundle]) error {
				t.Helper()

				if err := handle.emit(t.Context(), bundle); err != nil {
					return err
				}

				return handle.emit(
					t.Context(),
					types.NewCertificateBundle("bad", []*x509.Certificate{certificate}),
				)
			},
			wantValue:          "selector",
			wantOK:             true,
			wantConverterCalls: 2,
			wantErr:            assert.AnError,
		},
		"identity converter cannot cast": {
			emit: func(t *testing.T, handle *testHandle[CertificateBundle]) error {
				t.Helper()

				return handle.emit(t.Context(), bundle)
			},
			wantOK:  false,
			wantErr: ErrSecretConversionFailed,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			handle := newTestHandle[CertificateBundle]()
			resolver := &testResolver{certificateBundleHandle: handle}

			converterCalls := 0
			opts := wrapCertificateBundleConverters(tc.opts, &converterCalls)

			informer, err := NewCertificateBundleInformer(
				t.Context(),
				resolver,
				Reference{Source: "src", Selector: "selector"},
				opts...,
			)
			require.NoError(t, err)

			if tc.emit != nil {
				err = tc.emit(t, handle)
				if tc.wantErr != nil {
					require.Error(t, err)
					require.ErrorIs(t, err, tc.wantErr)
				} else {
					require.NoError(t, err)
				}
			}

			got, ok := informer.Get()

			require.Equal(t, tc.wantOK, ok)
			require.Equal(t, tc.wantValue, got)
			require.Equal(t, tc.wantConverterCalls, converterCalls)
		})
	}
}

func TestCertificateBundleInformerGetUsesIdentityConverter(t *testing.T) {
	t.Parallel()

	bundle := types.NewCertificateBundle("selector", nil)
	handle := newTestHandle[CertificateBundle]()
	resolver := &testResolver{certificateBundleHandle: handle}

	informer, err := NewCertificateBundleInformer[CertificateBundle](
		t.Context(),
		resolver,
		Reference{Source: "src", Selector: "selector"},
	)
	require.NoError(t, err)

	require.NoError(t, handle.emit(t.Context(), bundle))

	got, ok := informer.Get()

	require.True(t, ok)
	require.Equal(t, bundle, got)
}

func TestCertificateBundleInformerAwaitReady(t *testing.T) {
	t.Parallel()

	bundle := types.NewCertificateBundle("selector", nil)

	for uc, tc := range map[string]struct {
		converter func(t *testing.T, bundle CertificateBundle) (string, error)
		assert    func(t *testing.T, err error)
	}{
		"returns nil after successful conversion": {
			converter: func(t *testing.T, bundle CertificateBundle) (string, error) {
				t.Helper()

				return bundle.Selector(), nil
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"returns last conversion error on context cancellation": {
			converter: func(t *testing.T, _ CertificateBundle) (string, error) {
				t.Helper()

				return "", assert.AnError
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

			handle := newTestHandle[CertificateBundle]()
			resolver := &testResolver{certificateBundleHandle: handle}

			_, err := NewCertificateBundleInformer(
				t.Context(),
				resolver,
				Reference{Source: "src", Selector: "selector"},
				WithConverter(func(bundle CertificateBundle) (string, error) {
					return tc.converter(t, bundle)
				}),
			)
			require.NoError(t, err)

			_ = handle.emit(t.Context(), bundle)

			ctx, cancel := context.WithCancel(t.Context())
			cancel()

			tc.assert(t, handle.awaitReady(ctx))
		})
	}
}

func TestCertificateBundleInformerRegistersOnUpdateCallback(t *testing.T) {
	t.Parallel()

	bundle := types.NewCertificateBundle("selector", nil)
	handle := newTestHandle[CertificateBundle]()
	resolver := &testResolver{certificateBundleHandle: handle}

	userCallbackCalled := false

	informer, err := NewCertificateBundleInformer(
		t.Context(),
		resolver,
		Reference{Source: "src", Selector: "selector"},
		WithConverter(func(bundle CertificateBundle) (string, error) {
			return bundle.Selector(), nil
		}),
		WithUpdateCallback(func(_ context.Context, got CertificateBundle, value string) error {
			userCallbackCalled = true

			require.Equal(t, bundle, got)
			require.Equal(t, "selector", value)

			return nil
		}),
	)

	require.NoError(t, err)
	require.NotNil(t, informer)

	require.NoError(t, handle.emit(t.Context(), bundle))
	require.True(t, userCallbackCalled)
}

func wrapSecretConverters(
	opts []SecretInformerOption[string],
	calls *int,
) []SecretInformerOption[string] {
	wrapped := append([]SecretInformerOption[string]{}, opts...)

	for idx, opt := range opts {
		var cfg informerOptions[Secret, string]
		opt(&cfg)

		if cfg.converter == nil {
			continue
		}

		converter := cfg.converter
		wrapped[idx] = WithConverter(func(secret Secret) (string, error) {
			*calls++

			return converter(secret)
		})
	}

	return wrapped
}

func wrapCredentialsConverters(
	opts []CredentialsInformerOption[string],
	calls *int,
) []CredentialsInformerOption[string] {
	wrapped := append([]CredentialsInformerOption[string]{}, opts...)

	for idx, opt := range opts {
		var cfg informerOptions[Credentials, string]
		opt(&cfg)

		if cfg.converter == nil {
			continue
		}

		converter := cfg.converter
		wrapped[idx] = WithConverter(func(credentials Credentials) (string, error) {
			*calls++

			return converter(credentials)
		})
	}

	return wrapped
}

func wrapCertificateBundleConverters(
	opts []CertificateBundleInformerOption[string],
	calls *int,
) []CertificateBundleInformerOption[string] {
	wrapped := append([]CertificateBundleInformerOption[string]{}, opts...)

	for idx, opt := range opts {
		var cfg informerOptions[CertificateBundle, string]
		opt(&cfg)

		if cfg.converter == nil {
			continue
		}

		converter := cfg.converter
		wrapped[idx] = WithConverter(func(bundle CertificateBundle) (string, error) {
			*calls++

			return converter(bundle)
		})
	}

	return wrapped
}

type testResolver struct {
	secretHandle SecretHandle
	secretErr    error
	secretRef    Reference

	credentialsHandle CredentialsHandle
	credentialsErr    error
	credentialsRef    Reference

	certificateBundleHandle CertificateBundleHandle
	certificateBundleErr    error
	certificateBundleRef    Reference
}

func (r *testResolver) Secret(
	_ context.Context,
	ref Reference,
) (SecretHandle, error) {
	r.secretRef = ref

	if r.secretErr != nil {
		return nil, r.secretErr
	}

	return r.secretHandle, nil
}

func (r *testResolver) SecretSet(
	context.Context,
	Reference,
) (SecretSetHandle, error) {
	panic("not implemented")
}

func (r *testResolver) Credentials(
	_ context.Context,
	ref Reference,
) (CredentialsHandle, error) {
	r.credentialsRef = ref

	if r.credentialsErr != nil {
		return nil, r.credentialsErr
	}

	return r.credentialsHandle, nil
}

func (r *testResolver) CertificateBundle(
	_ context.Context,
	ref Reference,
) (CertificateBundleHandle, error) {
	r.certificateBundleRef = ref

	if r.certificateBundleErr != nil {
		return nil, r.certificateBundleErr
	}

	return r.certificateBundleHandle, nil
}

type testHandle[T any] struct {
	value T
	ok    bool

	callback  UpdateFunc[T]
	readiness []func(context.Context) error
}

func newTestHandle[T any]() *testHandle[T] {
	return &testHandle[T]{}
}

func (h *testHandle[T]) Get() (T, bool) {
	return h.value, h.ok
}

func (h *testHandle[T]) OnUpdate(callback UpdateFunc[T]) {
	h.callback = callback
}

func (h *testHandle[T]) registerReadiness(await func(context.Context) error) {
	h.readiness = append(h.readiness, await)
}

func (h *testHandle[T]) emit(ctx context.Context, value T) error {
	h.value = value
	h.ok = true

	if h.callback == nil {
		return nil
	}

	return h.callback(ctx, value)
}

func (h *testHandle[T]) awaitReady(ctx context.Context) error {
	for _, await := range h.readiness {
		if err := await(ctx); err != nil {
			return err
		}
	}

	return nil
}

var (
	_ Resolver                = (*testResolver)(nil)
	_ SecretHandle            = (*testHandle[Secret])(nil)
	_ SecretSetHandle         = (*testHandle[[]Secret])(nil)
	_ CredentialsHandle       = (*testHandle[Credentials])(nil)
	_ CertificateBundleHandle = (*testHandle[CertificateBundle])(nil)
	_ readinessRegistrar      = (*testHandle[Secret])(nil)
)
