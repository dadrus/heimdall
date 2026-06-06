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

package jwks

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/goccy/go-json"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/secrets/provider"
	"github.com/dadrus/heimdall/internal/secrets/provider/mocks"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/x/fswatch"
)

func TestNewProvider(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		config func(t *testing.T, path string) map[string]any
		assert func(t *testing.T, err error, prv *jwksProvider)
	}{
		"creates provider": {
			config: func(t *testing.T, path string) map[string]any {
				t.Helper()

				return map[string]any{"path": path}
			},
			assert: func(t *testing.T, err error, prv *jwksProvider) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, prv)

				assert.Equal(t, providerType, prv.Type())
				assert.Empty(t, prv.Dependencies())
				assert.False(t, prv.IsNamespaceAware())
				assert.NotEmpty(t, prv.path)
				assert.Nil(t, prv.watcher)
			},
		},
		"creates provider with watch enabled": {
			config: func(t *testing.T, path string) map[string]any {
				t.Helper()

				return map[string]any{"path": path, "watch": true}
			},
			assert: func(t *testing.T, err error, prv *jwksProvider) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, prv)

				assert.Equal(t, providerType, prv.Type())
				assert.Empty(t, prv.Dependencies())
				assert.False(t, prv.IsNamespaceAware())
				assert.NotEmpty(t, prv.path)
				assert.NotNil(t, prv.watcher)
			},
		},
		"fails if path is missing": {
			config: func(t *testing.T, _ string) map[string]any {
				t.Helper()

				return map[string]any{}
			},
			assert: func(t *testing.T, err error, prv *jwksProvider) {
				t.Helper()

				require.Error(t, err)
				require.Nil(t, prv)
				require.ErrorContains(t, err, "path")
			},
		},
		"fails for invalid watch field": {
			config: func(t *testing.T, path string) map[string]any {
				t.Helper()

				return map[string]any{"path": path, "watch": "yes"}
			},
			assert: func(t *testing.T, err error, prv *jwksProvider) {
				t.Helper()

				require.Error(t, err)
				require.Nil(t, prv)
				require.ErrorContains(t, err, "watch")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "keys.jwks")

			validator, err := validation.NewValidator()
			require.NoError(t, err)

			df := encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct))
			prv, err := newProvider(provider.Args{
				Config:         tc.config(t, path),
				Logger:         zerolog.Nop(),
				DecoderFactory: df,
				Observer:       mocks.NewChangeObserverMock(t),
			})

			var jwksPrv *jwksProvider
			if err == nil {
				jwksPrv = prv.(*jwksProvider)
			}

			tc.assert(t, err, jwksPrv)
		})
	}
}

func TestProviderGetSecret(t *testing.T) {
	t.Parallel()

	prv := &jwksProvider{
		store: keyStore{
			provider.NewSymmetricKeySecret("first", "first", "HS256", []byte("0123456789abcdef")),
			provider.NewSymmetricKeySecret("second", "second", "HS384", []byte("0123456789abcdef0123456789abcdef")),
		},
	}

	for uc, tc := range map[string]struct {
		selector provider.Selector
		assert   func(t *testing.T, secret provider.Secret, err error)
	}{
		"returns first entry for empty selector": {
			assert: func(t *testing.T, secret provider.Secret, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, secret)
				assert.Equal(t, "first", secret.Selector())
			},
		},
		"returns selected entry": {
			selector: provider.Selector{Value: "second"},
			assert: func(t *testing.T, secret provider.Secret, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, secret)
				assert.Equal(t, "second", secret.Selector())
			},
		},
		"returns not found error": {
			selector: provider.Selector{Value: "missing"},
			assert: func(t *testing.T, secret provider.Secret, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrSecretNotFound)
				require.Nil(t, secret)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			secret, err := prv.GetSecret(t.Context(), tc.selector)
			tc.assert(t, secret, err)
		})
	}
}

func TestProviderGetSecretSet(t *testing.T) {
	t.Parallel()

	prv := &jwksProvider{
		store: keyStore{
			provider.NewSymmetricKeySecret("first", "first", "HS256", []byte("0123456789abcdef")),
			provider.NewSymmetricKeySecret("second", "second", "HS384", []byte("0123456789abcdef0123456789abcdef")),
		},
	}

	secrets, err := prv.GetSecretSet(t.Context(), provider.Selector{Value: "ignored"})

	require.NoError(t, err)
	require.Len(t, secrets, 2)
	assert.Equal(t, "first", secrets[0].Selector())
	assert.Equal(t, "second", secrets[1].Selector())
}

func TestProviderGetCredentials(t *testing.T) {
	t.Parallel()

	prv := &jwksProvider{}

	credentials, err := prv.GetCredentials(t.Context(), provider.Selector{})

	require.Error(t, err)
	require.ErrorIs(t, err, provider.ErrUnsupportedOperation)
	require.Nil(t, credentials)
}

func TestProviderGetCertificateBundle(t *testing.T) {
	t.Parallel()

	prv := &jwksProvider{
		store: keyStore{},
	}

	bundle, err := prv.GetCertificateBundle(t.Context(), provider.Selector{})

	require.Error(t, err)
	require.ErrorIs(t, err, provider.ErrUnsupportedOperation)
	require.Nil(t, bundle)
}

func TestProviderLifecycleManagement(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		config      func(t *testing.T, path string) map[string]any
		setupMock   func(t *testing.T, observer *mocks.ChangeObserverMock)
		beforeStart func(t *testing.T, path string)
		afterStart  func(t *testing.T, path string)
		event       fswatch.Event
		assert      func(t *testing.T, prv *jwksProvider, err error)
	}{
		"fails loading store": {
			config: func(t *testing.T, path string) map[string]any {
				t.Helper()

				return map[string]any{"path": path}
			},
			beforeStart: func(t *testing.T, path string) {
				t.Helper()

				require.NoError(t, os.WriteFile(path, []byte(`{`), 0o600))
			},
			assert: func(t *testing.T, prv *jwksProvider, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				assert.Nil(t, prv.store)
			},
		},
		"starts without watching for changes": {
			config: func(t *testing.T, path string) map[string]any {
				t.Helper()

				return map[string]any{"path": path, "watch": false}
			},
			beforeStart: func(t *testing.T, path string) {
				t.Helper()

				raw, err := json.Marshal(jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{
						{
							Key:   []byte("0123456789abcdef"),
							KeyID: "initial",
						},
					},
				})
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(path, raw, 0o600))
			},
			assert: func(t *testing.T, prv *jwksProvider, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, prv.store)
				assert.Nil(t, prv.watcher)

				secret, err := prv.GetSecret(t.Context(), provider.Selector{})
				require.NoError(t, err)
				assert.Equal(t, "initial", secret.Selector())
			},
		},
		"starts with watching for changes": {
			config: func(t *testing.T, path string) map[string]any {
				t.Helper()

				return map[string]any{"path": path, "watch": true}
			},
			beforeStart: func(t *testing.T, path string) {
				t.Helper()

				raw, err := json.Marshal(jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{
						{
							Key:   []byte("0123456789abcdef"),
							KeyID: "initial",
						},
					},
				})
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(path, raw, 0o600))
			},
			assert: func(t *testing.T, prv *jwksProvider, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, prv.store)
				assert.NotNil(t, prv.watcher)

				secret, err := prv.GetSecret(t.Context(), provider.Selector{})
				require.NoError(t, err)
				assert.Equal(t, "initial", secret.Selector())
			},
		},
		"ignores non-change events": {
			config: func(t *testing.T, path string) map[string]any {
				t.Helper()

				return map[string]any{"path": path}
			},
			beforeStart: func(t *testing.T, path string) {
				t.Helper()

				raw, err := json.Marshal(jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{
						{
							Key:   []byte("0123456789abcdef"),
							KeyID: "initial",
						},
					},
				})
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(path, raw, 0o600))
			},
			afterStart: func(t *testing.T, path string) {
				t.Helper()

				raw, err := json.Marshal(jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{
						{
							Key:   []byte("0123456789abcdef"),
							KeyID: "reloaded",
						},
					},
				})
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(path, raw, 0o600))
			},
			event: fswatch.Event{Op: fswatch.OpAdded},
			assert: func(t *testing.T, prv *jwksProvider, err error) {
				t.Helper()

				require.NoError(t, err)

				secret, err := prv.GetSecret(t.Context(), provider.Selector{})
				require.NoError(t, err)
				assert.Equal(t, "initial", secret.Selector())
			},
		},
		"reloads changed file": {
			config: func(t *testing.T, path string) map[string]any {
				t.Helper()

				return map[string]any{"path": path}
			},
			setupMock: func(t *testing.T, observer *mocks.ChangeObserverMock) {
				t.Helper()

				observer.EXPECT().
					Notify(mock.MatchedBy(func(e provider.ChangeEvent) bool {
						return len(e.Selectors) == 0
					})).
					Once()
			},
			beforeStart: func(t *testing.T, path string) {
				t.Helper()

				raw, err := json.Marshal(jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{
						{
							Key:   []byte("0123456789abcdef"),
							KeyID: "initial",
						},
					},
				})
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(path, raw, 0o600))
			},
			afterStart: func(t *testing.T, path string) {
				t.Helper()

				raw, err := json.Marshal(jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{
						{
							Key:   []byte("0123456789abcdef"),
							KeyID: "reloaded",
						},
					},
				})
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(path, raw, 0o600))
			},
			event: fswatch.Event{Op: fswatch.OpChanged},
			assert: func(t *testing.T, prv *jwksProvider, err error) {
				t.Helper()

				require.NoError(t, err)

				secret, err := prv.GetSecret(t.Context(), provider.Selector{})
				require.NoError(t, err)
				assert.Equal(t, "reloaded", secret.Selector())
			},
		},
		"keeps old store if reload fails": {
			config: func(t *testing.T, path string) map[string]any {
				t.Helper()

				return map[string]any{"path": path}
			},
			beforeStart: func(t *testing.T, path string) {
				t.Helper()

				raw, err := json.Marshal(jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{
						{
							Key:   []byte("0123456789abcdef"),
							KeyID: "initial",
						},
					},
				})
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(path, raw, 0o600))
			},
			afterStart: func(t *testing.T, path string) {
				t.Helper()

				require.NoError(t, os.WriteFile(path, []byte(`{`), 0o600))
			},
			event: fswatch.Event{Op: fswatch.OpChanged},
			assert: func(t *testing.T, prv *jwksProvider, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)

				secret, err := prv.GetSecret(t.Context(), provider.Selector{})
				require.NoError(t, err)
				assert.Equal(t, "initial", secret.Selector())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "keys.jwks")
			tc.beforeStart(t, path)

			observer := mocks.NewChangeObserverMock(t)
			if tc.setupMock != nil {
				tc.setupMock(t, observer)
			}

			validator, err := validation.NewValidator()
			require.NoError(t, err)

			df := encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct))
			prv, err := newProvider(provider.Args{
				Config:         tc.config(t, path),
				Logger:         zerolog.Nop(),
				DecoderFactory: df,
				Observer:       observer,
			})
			require.NoError(t, err)

			jwksPrv := prv.(*jwksProvider)

			err = jwksPrv.Start(t.Context())
			t.Cleanup(func() {
				_ = jwksPrv.Stop(context.Background())
			})

			if err == nil && tc.afterStart != nil {
				tc.afterStart(t, path)
				err = jwksPrv.reload(tc.event)
			}

			tc.assert(t, jwksPrv, err)
		})
	}
}
