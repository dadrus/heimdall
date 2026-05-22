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

package pem

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/secrets/provider"
	"github.com/dadrus/heimdall/internal/secrets/provider/mocks"
	"github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/x/pkix/pemx"
)

func TestNewProvider(t *testing.T) {
	t.Parallel()

	pemFile := createPEMFile(t, "first", "second")

	for uc, tc := range map[string]struct {
		conf   map[string]any
		assert func(*testing.T, error, provider.Provider)
	}{
		"successfully creates provider": {
			conf: map[string]any{"path": pemFile},
			assert: func(t *testing.T, err error, provider provider.Provider) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, "pem", provider.Type())
			},
		},
		"fails for missing path config": {
			conf: map[string]any{},
			assert: func(t *testing.T, err error, _ provider.Provider) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "path")
			},
		},
		"fails for invalid watch field": {
			conf: map[string]any{"path": pemFile, "watch": "yes"},
			assert: func(t *testing.T, err error, _ provider.Provider) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "watch")
			},
		},
		"fails for invalid path": {
			conf: map[string]any{"path": "does_not_exist.pem"},
			assert: func(t *testing.T, err error, _ provider.Provider) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "does_not_exist.pem")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			validator, err := validation.NewValidator()
			require.NoError(t, err)

			prv, err := newProvider(provider.Args{
				Config:         tc.conf,
				Logger:         zerolog.Nop(),
				DecoderFactory: encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct)),
			})
			tc.assert(t, err, prv)
		})
	}
}

func TestProviderWatch(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, om *mocks.ChangeObserverMock)
		action func(t *testing.T, prv provider.Provider, path string)
	}{
		"does nothing if watch is disabled": {
			setup: func(t *testing.T, om *mocks.ChangeObserverMock) {
				t.Helper()
			},
			action: func(t *testing.T, prv provider.Provider, _ string) {
				t.Helper()

				require.NoError(t, prv.Start(context.Background()))
				require.NoError(t, prv.Stop(context.Background()))
			},
		},
		"returns error if watch target cannot be registered": {
			setup: func(t *testing.T, om *mocks.ChangeObserverMock) {
				t.Helper()
			},
			action: func(t *testing.T, prv provider.Provider, path string) {
				t.Helper()

				require.NoError(t, os.Remove(path))

				err := prv.Start(context.Background())
				require.Error(t, err)
				require.ErrorContains(t, err, "failed to register pem provider watch")
			},
		},
		"reloads source on file change and emits source event": {
			setup: func(t *testing.T, om *mocks.ChangeObserverMock) {
				t.Helper()

				om.EXPECT().Notify(mock.MatchedBy(func(e provider.ChangeEvent) bool {
					return len(e.Selectors) == 0
				}))
			},
			action: func(t *testing.T, prv provider.Provider, path string) {
				t.Helper()
				t.Cleanup(func() { _ = prv.Stop(context.Background()) })

				err := prv.Start(context.Background())
				require.NoError(t, err)
				time.Sleep(100 * time.Millisecond)

				writePEMFile(t, path, "second")
				time.Sleep(100 * time.Millisecond)

				secret, err := prv.GetSecret(context.Background(), provider.Selector{})
				require.NoError(t, err)
				require.Equal(t, "second", secret.Selector())
			},
		},
		"keeps last-known-good key material if reload fails": {
			setup: func(t *testing.T, om *mocks.ChangeObserverMock) {
				t.Helper()
			},
			action: func(t *testing.T, prv provider.Provider, path string) {
				t.Helper()
				t.Cleanup(func() { _ = prv.Stop(context.Background()) })

				err := prv.Start(context.Background())
				require.NoError(t, err)
				time.Sleep(100 * time.Millisecond)

				err = os.WriteFile(path, []byte("not a pem file"), 0o600)
				require.NoError(t, err)
				time.Sleep(100 * time.Millisecond)

				secret, err := prv.GetSecret(context.Background(), provider.Selector{})
				require.NoError(t, err)
				require.Equal(t, "first", secret.Selector())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			pemFile := createPEMFile(t, "first")
			watch := uc != "does nothing if watch is disabled"
			validator, err := validation.NewValidator()
			require.NoError(t, err)

			om := mocks.NewChangeObserverMock(t)
			tc.setup(t, om)

			prv, err := newProvider(provider.Args{
				Config:         map[string]any{"path": pemFile, "watch": watch},
				Logger:         zerolog.Nop(),
				DecoderFactory: encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct)),
				Observer:       om,
			})
			require.NoError(t, err)

			tc.action(t, prv, pemFile)
		})
	}
}

func TestProviderGetSecret(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		selector provider.Selector
		provider *pemProvider
		assert   func(*testing.T, error, types.Secret)
	}{
		"returns first secret for empty selector": {
			provider: newPEMProviderForTest(t, "first", "second"),
			selector: provider.Selector{},
			assert: func(t *testing.T, err error, secret types.Secret) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "first", secret.Selector())
			},
		},
		"returns matching secret for explicit selector": {
			provider: newPEMProviderForTest(t, "first", "second"),
			selector: provider.Selector{Value: "second"},
			assert: func(t *testing.T, err error, secret types.Secret) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "second", secret.Selector())
			},
		},
		"fails for unknown selector": {
			provider: newPEMProviderForTest(t, "first", "second"),
			selector: provider.Selector{Value: "third"},
			assert: func(t *testing.T, err error, _ types.Secret) {
				t.Helper()

				require.ErrorIs(t, err, types.ErrSecretNotFound)
			},
		},
		"fails if key store is empty": {
			provider: &pemProvider{},
			assert: func(t *testing.T, err error, _ types.Secret) {
				t.Helper()

				require.ErrorIs(t, err, types.ErrSecretNotFound)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			// WHEN
			secret, err := tc.provider.GetSecret(t.Context(), tc.selector)

			// THEN
			tc.assert(t, err, secret)
		})
	}
}

func TestProviderGetSecretSet(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		selector provider.Selector
		provider *pemProvider
		assert   func(*testing.T, error, []types.Secret)
	}{
		"returns all secrets for empty selector": {
			provider: newPEMProviderForTest(t, "first", "second"),
			assert: func(t *testing.T, err error, secretSet []types.Secret) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, secretSet, 2)
				assert.Equal(t, []string{"first", "second"}, selectorsFromSecretSet(secretSet))
			},
		},
		"returns all secrets regardless of selector": {
			provider: newPEMProviderForTest(t, "first", "second"),
			selector: provider.Selector{Value: "ignored"},
			assert: func(t *testing.T, err error, secretSet []types.Secret) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, secretSet, 2)
				assert.Equal(t, []string{"first", "second"}, selectorsFromSecretSet(secretSet))
			},
		},
		"returns empty set if key store is empty": {
			provider: &pemProvider{},
			assert: func(t *testing.T, err error, secretSet []types.Secret) {
				t.Helper()

				require.NoError(t, err)
				assert.Empty(t, secretSet)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			// WHEN
			secretSet, err := tc.provider.GetSecretSet(t.Context(), tc.selector)

			// THEN
			tc.assert(t, err, secretSet)
		})
	}
}

func TestProviderGetCredentials(t *testing.T) {
	t.Parallel()

	// GIVEN
	prov := &pemProvider{}

	// WHEN
	_, err := prov.GetCredentials(t.Context(), provider.Selector{})

	// THEN
	require.ErrorIs(t, err, types.ErrUnsupportedOperation)
}

func createPEMFile(t *testing.T, keyIDs ...string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "keys.pem")
	writePEMFile(t, path, keyIDs...)

	return path
}

func newPEMProviderForTest(t *testing.T, keyIDs ...string) *pemProvider {
	t.Helper()

	pemFile := createPEMFile(t, keyIDs...)
	validator, err := validation.NewValidator()
	require.NoError(t, err)

	prov, err := newProvider(provider.Args{
		Config:         map[string]any{"path": pemFile},
		Logger:         zerolog.Nop(),
		DecoderFactory: encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct)),
	})
	require.NoError(t, err)

	concrete, ok := prov.(*pemProvider)
	require.True(t, ok)

	return concrete
}

func selectorsFromSecretSet(secretSet []types.Secret) []string {
	selectors := make([]string, len(secretSet))
	for idx, secret := range secretSet {
		selectors[idx] = secret.Selector()
	}

	return selectors
}

func writePEMFile(t *testing.T, path string, keyIDs ...string) {
	t.Helper()

	opts := make([]pemx.EntryOption, 0, len(keyIDs))
	for _, keyID := range keyIDs {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		opts = append(opts, pemx.WithRSAPrivateKey(key, pemx.WithHeader("X-Key-ID", keyID)))
	}

	data, err := pemx.BuildPEM(opts...)
	require.NoError(t, err)

	err = os.WriteFile(path, data, 0o600)
	require.NoError(t, err)
}
