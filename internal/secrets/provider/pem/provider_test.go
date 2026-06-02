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
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/x/fswatch"
	"github.com/dadrus/heimdall/internal/x/pkix/pemx"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestLoadStore(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		path   func(t *testing.T) string
		assert func(t *testing.T, st store, err error)
	}{
		"loads key store from pem file": {
			path: func(t *testing.T) string {
				t.Helper()

				path := filepath.Join(t.TempDir(), "keys.pem")
				writePEMFile(t, path, "first", "second")

				return path
			},
			assert: func(t *testing.T, st store, err error) {
				t.Helper()

				require.NoError(t, err)

				ks, ok := st.(keyStore)
				require.True(t, ok)
				require.Len(t, ks, 2)
				require.Equal(t, "first", ks[0].Selector())
				require.Equal(t, "second", ks[1].Selector())
			},
		},
		"loads certificate store from pem file": {
			path: func(t *testing.T) string {
				t.Helper()

				path := filepath.Join(t.TempDir(), "certs.pem")
				writeCertificatePEMFile(t, path, "first", "second")

				return path
			},
			assert: func(t *testing.T, st store, err error) {
				t.Helper()

				require.NoError(t, err)

				cs, ok := st.(certStore)
				require.True(t, ok)
				require.Len(t, cs, 2)
				require.Equal(t, "first", cs[0].Subject.CommonName)
				require.Equal(t, "second", cs[1].Subject.CommonName)
			},
		},
		"fails if file does not exist": {
			path: func(t *testing.T) string {
				t.Helper()

				return filepath.Join(t.TempDir(), "missing.pem")
			},
			assert: func(t *testing.T, st store, err error) {
				t.Helper()

				require.Nil(t, st)
				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "failed to read pem file")
			},
		},
		"fails if pem file cannot be parsed": {
			path: func(t *testing.T) string {
				t.Helper()

				path := filepath.Join(t.TempDir(), "keys.pem")
				require.NoError(t, os.WriteFile(path, []byte("not a pem file"), 0o600))

				return path
			},
			assert: func(t *testing.T, st store, err error) {
				t.Helper()

				require.Nil(t, st)
				require.Error(t, err)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			st, err := loadStore(tc.path(t), "")
			tc.assert(t, st, err)
		})
	}
}

func TestNewProvider(t *testing.T) {
	t.Parallel()

	pemFile := filepath.Join(t.TempDir(), "keys.pem")

	for uc, tc := range map[string]struct {
		conf   map[string]any
		assert func(t *testing.T, err error, prv *pemProvider)
	}{
		"creates provider": {
			conf: map[string]any{"path": pemFile},
			assert: func(t *testing.T, err error, prv *pemProvider) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, providerType, prv.Type())
				assert.Empty(t, prv.Dependencies())
				assert.False(t, prv.IsNamespaceAware())
				assert.Nil(t, prv.watcher)
				assert.Equal(t, pemFile, prv.path)
			},
		},
		"creates provider with watch enabled": {
			conf: map[string]any{"path": pemFile, "watch": true},
			assert: func(t *testing.T, err error, prv *pemProvider) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, providerType, prv.Type())
				assert.Empty(t, prv.Dependencies())
				assert.False(t, prv.IsNamespaceAware())
				assert.NotNil(t, prv.watcher)
				assert.Equal(t, pemFile, prv.path)
			},
		},
		"fails for missing path config": {
			conf: map[string]any{},
			assert: func(t *testing.T, err error, _ *pemProvider) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "path")
			},
		},
		"fails for invalid watch field": {
			conf: map[string]any{"path": pemFile, "watch": "yes"},
			assert: func(t *testing.T, err error, _ *pemProvider) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "watch")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			validator, err := validation.NewValidator()
			require.NoError(t, err)

			df := encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct))

			prv, err := newProvider(provider.Args{
				Config:         tc.conf,
				Logger:         zerolog.Nop(),
				DecoderFactory: df,
				Observer:       mocks.NewChangeObserverMock(t),
			})

			var pemPrv *pemProvider
			if err == nil {
				pemPrv = prv.(*pemProvider)
			}

			tc.assert(t, err, pemPrv)
		})
	}
}

func TestProviderStart(t *testing.T) {
	t.Parallel()

	pemFile := filepath.Join(t.TempDir(), "keys.pem")
	writePEMFile(t, pemFile, "first")

	for uc, tc := range map[string]struct {
		conf   map[string]any
		assert func(t *testing.T, err error, prv *pemProvider)
	}{
		"fails loading pem file": {
			conf: map[string]any{"path": filepath.Join(t.TempDir(), "missing.pem")},
			assert: func(t *testing.T, err error, prv *pemProvider) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "failed to read pem file")
				assert.Nil(t, prv.store)
			},
		},
		"successfully loads pem file and starts without watching for changes": {
			conf: map[string]any{"path": pemFile, "watch": false},
			assert: func(t *testing.T, err error, prv *pemProvider) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, prv.store)
				assert.Nil(t, prv.watcher)

				ks, ok := prv.store.(keyStore)
				require.True(t, ok)
				require.Len(t, ks, 1)
				assert.Equal(t, "first", ks[0].Selector())
			},
		},
		"successfully loads pem file and starts with watching for changes": {
			conf: map[string]any{"path": pemFile, "watch": true},
			assert: func(t *testing.T, err error, prv *pemProvider) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, prv.store)
				assert.NotNil(t, prv.watcher)

				ks, ok := prv.store.(keyStore)
				require.True(t, ok)
				require.Len(t, ks, 1)
				assert.Equal(t, "first", ks[0].Selector())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			validator, err := validation.NewValidator()
			require.NoError(t, err)

			df := encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct))

			prv, err := newProvider(provider.Args{
				Config:         tc.conf,
				Logger:         zerolog.Nop(),
				DecoderFactory: df,
				Observer:       mocks.NewChangeObserverMock(t),
			})
			require.NoError(t, err)

			err = prv.Start(t.Context())

			t.Cleanup(func() {
				_ = prv.Stop(context.Background())
			})

			tc.assert(t, err, prv.(*pemProvider))
		})
	}
}

func TestProviderReload(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		path   func(t *testing.T) string
		event  fswatch.Event
		setup  func(t *testing.T, path string, om *mocks.ChangeObserverMock)
		assert func(t *testing.T, err error, prv *pemProvider)
	}{
		"ignores non-change events": {
			path: func(t *testing.T) string {
				t.Helper()

				path := filepath.Join(t.TempDir(), "keys.pem")
				writePEMFile(t, path, "first")

				return path
			},
			event: fswatch.Event{},
			setup: func(t *testing.T, path string, _ *mocks.ChangeObserverMock) {
				t.Helper()

				writePEMFile(t, path, "second")
			},
			assert: func(t *testing.T, err error, prv *pemProvider) {
				t.Helper()

				require.NoError(t, err)

				ks, ok := prv.store.(keyStore)
				require.True(t, ok)
				require.Len(t, ks, 1)
				require.Equal(t, "first", ks[0].Selector())
			},
		},
		"reloads key material and emits source event": {
			path: func(t *testing.T) string {
				t.Helper()

				path := filepath.Join(t.TempDir(), "keys.pem")
				writePEMFile(t, path, "first")

				return path
			},
			event: fswatch.Event{Op: fswatch.OpChanged},
			setup: func(t *testing.T, path string, om *mocks.ChangeObserverMock) {
				t.Helper()

				writePEMFile(t, path, "second")

				om.EXPECT().Notify(mock.MatchedBy(func(e provider.ChangeEvent) bool {
					return len(e.Selectors) == 0
				}))
			},
			assert: func(t *testing.T, err error, prv *pemProvider) {
				t.Helper()

				require.NoError(t, err)

				ks, ok := prv.store.(keyStore)
				require.True(t, ok)
				require.Len(t, ks, 1)
				require.Equal(t, "second", ks[0].Selector())
			},
		},
		"reloads certificate bundle and emits source event": {
			path: func(t *testing.T) string {
				t.Helper()

				path := filepath.Join(t.TempDir(), "certs.pem")
				writeCertificatePEMFile(t, path, "first")

				return path
			},
			event: fswatch.Event{Op: fswatch.OpChanged},
			setup: func(t *testing.T, path string, om *mocks.ChangeObserverMock) {
				t.Helper()

				writeCertificatePEMFile(t, path, "second")

				om.EXPECT().Notify(mock.MatchedBy(func(e provider.ChangeEvent) bool {
					return len(e.Selectors) == 0
				}))
			},
			assert: func(t *testing.T, err error, prv *pemProvider) {
				t.Helper()

				require.NoError(t, err)

				cs, ok := prv.store.(certStore)
				require.True(t, ok)
				require.Len(t, cs, 1)
				require.Equal(t, "second", cs[0].Subject.CommonName)
			},
		},
		"keeps last-known-good key material if reload fails": {
			path: func(t *testing.T) string {
				t.Helper()

				path := filepath.Join(t.TempDir(), "keys.pem")
				writePEMFile(t, path, "first")

				return path
			},
			event: fswatch.Event{Op: fswatch.OpChanged},
			setup: func(t *testing.T, path string, _ *mocks.ChangeObserverMock) {
				t.Helper()

				require.NoError(t, os.WriteFile(path, []byte("not a pem file"), 0o600))
			},
			assert: func(t *testing.T, err error, prv *pemProvider) {
				t.Helper()

				require.Error(t, err)

				ks, ok := prv.store.(keyStore)
				require.True(t, ok)
				require.Len(t, ks, 1)
				require.Equal(t, "first", ks[0].Selector())
			},
		},
		"keeps last-known-good material if store kind changed": {
			path: func(t *testing.T) string {
				t.Helper()

				path := filepath.Join(t.TempDir(), "keys.pem")
				writePEMFile(t, path, "first")

				return path
			},
			event: fswatch.Event{Op: fswatch.OpChanged},
			setup: func(t *testing.T, path string, _ *mocks.ChangeObserverMock) {
				t.Helper()

				writeCertificatePEMFile(t, path, "certificate")
			},
			assert: func(t *testing.T, err error, prv *pemProvider) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "store kind changed")

				ks, ok := prv.store.(keyStore)
				require.True(t, ok)
				require.Len(t, ks, 1)
				require.Equal(t, "first", ks[0].Selector())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			path := tc.path(t)

			st, err := loadStore(path, "")
			require.NoError(t, err)

			om := mocks.NewChangeObserverMock(t)
			tc.setup(t, path, om)

			prv := &pemProvider{
				path:     path,
				logger:   zerolog.Nop(),
				observer: om,
				store:    st,
			}

			err = prv.reload(tc.event)

			tc.assert(t, err, prv)
		})
	}
}

func TestProviderWatch(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		path   func(t *testing.T) string
		setup  func(t *testing.T, om *mocks.ChangeObserverMock)
		action func(t *testing.T, prv provider.Provider, path string)
	}{
		"reloads source on file change and emits source event": {
			path: func(t *testing.T) string {
				t.Helper()

				path := filepath.Join(t.TempDir(), "keys.pem")
				writePEMFile(t, path, "first")

				return path
			},
			setup: func(t *testing.T, om *mocks.ChangeObserverMock) {
				t.Helper()

				om.EXPECT().Notify(mock.MatchedBy(func(e provider.ChangeEvent) bool {
					return len(e.Selectors) == 0
				}))
			},
			action: func(t *testing.T, prv provider.Provider, path string) {
				t.Helper()
				t.Cleanup(func() { require.NoError(t, prv.Stop(context.Background())) })

				require.NoError(t, prv.Start(t.Context()))
				writePEMFile(t, path, "second")

				require.Eventually(t, func() bool {
					secret, err := prv.GetSecret(t.Context(), provider.Selector{})
					if err != nil {
						return false
					}

					return secret.Selector() == "second"
				}, time.Second, 20*time.Millisecond)
			},
		},
		"reloads certificate bundle on file change and emits source event": {
			path: func(t *testing.T) string {
				t.Helper()

				path := filepath.Join(t.TempDir(), "certs.pem")
				writeCertificatePEMFile(t, path, "first")

				return path
			},
			setup: func(t *testing.T, om *mocks.ChangeObserverMock) {
				t.Helper()

				om.EXPECT().Notify(mock.MatchedBy(func(e provider.ChangeEvent) bool {
					return len(e.Selectors) == 0
				}))
			},
			action: func(t *testing.T, prv provider.Provider, path string) {
				t.Helper()
				t.Cleanup(func() { require.NoError(t, prv.Stop(context.Background())) })

				require.NoError(t, prv.Start(t.Context()))
				writeCertificatePEMFile(t, path, "second")

				require.Eventually(t, func() bool {
					bundle, err := prv.GetCertificateBundle(t.Context(), provider.Selector{})
					if err != nil {
						return false
					}

					certs := bundle.Certificates()

					return len(certs) == 1 && certs[0].Subject.CommonName == "second"
				}, time.Second, 20*time.Millisecond)
			},
		},
		"reloads source on atomic symlink update and emits source event": {
			path: func(t *testing.T) string {
				t.Helper()

				dir := t.TempDir()
				target := filepath.Join(dir, "keys-1.pem")
				writePEMFile(t, target, "first")

				path := filepath.Join(dir, "keys.pem")
				require.NoError(t, os.Symlink(target, path))

				return path
			},
			setup: func(t *testing.T, om *mocks.ChangeObserverMock) {
				t.Helper()

				om.EXPECT().Notify(mock.MatchedBy(func(e provider.ChangeEvent) bool {
					return len(e.Selectors) == 0
				}))
			},
			action: func(t *testing.T, prv provider.Provider, path string) {
				t.Helper()
				t.Cleanup(func() { require.NoError(t, prv.Stop(context.Background())) })

				require.NoError(t, prv.Start(t.Context()))

				dir := filepath.Dir(path)
				oldTarget := filepath.Join(dir, "keys-1.pem")
				newTarget := filepath.Join(dir, "keys-2.pem")

				writePEMFile(t, newTarget, "second")
				require.NoError(t, os.Remove(path))
				require.NoError(t, os.Symlink(newTarget, path))
				require.NoError(t, os.Chmod(oldTarget, 0o644))

				require.Eventually(t, func() bool {
					secret, err := prv.GetSecret(t.Context(), provider.Selector{})
					if err != nil {
						return false
					}

					return secret.Selector() == "second"
				}, time.Second, 20*time.Millisecond)
			},
		},
		"keeps last-known-good key material if reload fails": {
			path: func(t *testing.T) string {
				t.Helper()

				path := filepath.Join(t.TempDir(), "keys.pem")
				writePEMFile(t, path, "first")

				return path
			},
			setup: func(t *testing.T, _ *mocks.ChangeObserverMock) { t.Helper() },
			action: func(t *testing.T, prv provider.Provider, path string) {
				t.Helper()
				t.Cleanup(func() { require.NoError(t, prv.Stop(context.Background())) })

				require.NoError(t, prv.Start(t.Context()))

				time.Sleep(50 * time.Millisecond)

				require.NoError(t, os.WriteFile(path, []byte("not a pem file"), 0o600))

				time.Sleep(50 * time.Millisecond)

				secret, err := prv.GetSecret(t.Context(), provider.Selector{})
				require.NoError(t, err)
				require.Equal(t, "first", secret.Selector())
			},
		},
		"keeps last-known-good key material if file is gone": {
			path: func(t *testing.T) string {
				t.Helper()

				path := filepath.Join(t.TempDir(), "keys.pem")
				writePEMFile(t, path, "first")

				return path
			},
			setup: func(t *testing.T, _ *mocks.ChangeObserverMock) { t.Helper() },
			action: func(t *testing.T, prv provider.Provider, path string) {
				t.Helper()
				t.Cleanup(func() { require.NoError(t, prv.Stop(context.Background())) })

				require.NoError(t, prv.Start(t.Context()))

				time.Sleep(50 * time.Millisecond)

				require.NoError(t, os.Remove(path))

				time.Sleep(50 * time.Millisecond)

				secret, err := prv.GetSecret(t.Context(), provider.Selector{})
				require.NoError(t, err)
				require.Equal(t, "first", secret.Selector())
			},
		},
		"watcher is detached from startup context": {
			path: func(t *testing.T) string {
				t.Helper()

				path := filepath.Join(t.TempDir(), "keys.pem")
				writePEMFile(t, path, "first")

				return path
			},
			setup: func(t *testing.T, om *mocks.ChangeObserverMock) {
				t.Helper()

				om.EXPECT().Notify(mock.MatchedBy(func(e provider.ChangeEvent) bool {
					return len(e.Selectors) == 0
				}))
			},
			action: func(t *testing.T, prv provider.Provider, path string) {
				t.Helper()
				t.Cleanup(func() { require.NoError(t, prv.Stop(context.Background())) })

				startCtx, cancelStart := context.WithCancel(t.Context())
				require.NoError(t, prv.Start(startCtx))
				cancelStart()

				writePEMFile(t, path, "second")

				require.Eventually(t, func() bool {
					secret, err := prv.GetSecret(t.Context(), provider.Selector{})
					if err != nil {
						return false
					}

					return secret.Selector() == "second"
				}, time.Second, 20*time.Millisecond)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			path := tc.path(t)

			om := mocks.NewChangeObserverMock(t)
			tc.setup(t, om)

			validator, err := validation.NewValidator()
			require.NoError(t, err)

			df := encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct))

			prv, err := newProvider(provider.Args{
				Config: map[string]any{
					"path":  path,
					"watch": true,
				},
				Logger:         zerolog.Nop(),
				DecoderFactory: df,
				Observer:       om,
			})
			require.NoError(t, err)

			tc.action(t, prv, path)
		})
	}
}

func TestProviderGetSecret(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "keys.pem")
	writePEMFile(t, path, "first", "second")

	validator, err := validation.NewValidator()
	require.NoError(t, err)

	df := encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct))

	prv, err := newProvider(provider.Args{
		Config:         map[string]any{"path": path, "watch": false},
		Logger:         zerolog.Nop(),
		DecoderFactory: df,
		Observer:       mocks.NewChangeObserverMock(t),
	})
	require.NoError(t, err)

	require.NoError(t, prv.Start(t.Context()))

	t.Cleanup(func() {
		_ = prv.Stop(context.Background())
	})

	for uc, tc := range map[string]struct {
		selector provider.Selector
		assert   func(t *testing.T, err error, secret provider.Secret)
	}{
		"returns first secret for empty selector": {
			selector: provider.Selector{},
			assert: func(t *testing.T, err error, secret provider.Secret) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, secret)
				require.Equal(t, "first", secret.Selector())
			},
		},
		"returns matching secret for explicit selector": {
			selector: provider.Selector{Value: "second"},
			assert: func(t *testing.T, err error, secret provider.Secret) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, secret)
				require.Equal(t, "second", secret.Selector())
			},
		},
		"fails for unknown selector": {
			selector: provider.Selector{Value: "third"},
			assert: func(t *testing.T, err error, _ provider.Secret) {
				t.Helper()

				require.ErrorIs(t, err, provider.ErrSecretNotFound)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			secret, err := prv.GetSecret(t.Context(), tc.selector)

			tc.assert(t, err, secret)
		})
	}
}

func TestProviderGetSecretFailsForCertificateStore(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "certs.pem")
	writeCertificatePEMFile(t, path, "first")

	validator, err := validation.NewValidator()
	require.NoError(t, err)

	df := encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct))

	prv, err := newProvider(provider.Args{
		Config:         map[string]any{"path": path, "watch": false},
		Logger:         zerolog.Nop(),
		DecoderFactory: df,
		Observer:       mocks.NewChangeObserverMock(t),
	})
	require.NoError(t, err)

	require.NoError(t, prv.Start(t.Context()))

	t.Cleanup(func() {
		_ = prv.Stop(context.Background())
	})

	secret, err := prv.GetSecret(t.Context(), provider.Selector{})

	require.ErrorIs(t, err, provider.ErrUnsupportedOperation)
	require.Nil(t, secret)
}

func TestProviderGetSecretSet(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "keys.pem")
	writePEMFile(t, path, "first", "second")

	validator, err := validation.NewValidator()
	require.NoError(t, err)

	df := encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct))

	prv, err := newProvider(provider.Args{
		Config:         map[string]any{"path": path, "watch": false},
		Logger:         zerolog.Nop(),
		DecoderFactory: df,
		Observer:       mocks.NewChangeObserverMock(t),
	})
	require.NoError(t, err)

	require.NoError(t, prv.Start(t.Context()))

	t.Cleanup(func() {
		_ = prv.Stop(context.Background())
	})

	for uc, tc := range map[string]struct {
		selector provider.Selector
		assert   func(t *testing.T, err error, secretSet []provider.Secret)
	}{
		"returns all secrets for empty selector": {
			selector: provider.Selector{},
			assert: func(t *testing.T, err error, secretSet []provider.Secret) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, secretSet, 2)
				require.Equal(t, "first", secretSet[0].Selector())
				require.Equal(t, "second", secretSet[1].Selector())
			},
		},
		"returns all secrets regardless of selector": {
			selector: provider.Selector{Value: "ignored"},
			assert: func(t *testing.T, err error, secretSet []provider.Secret) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, secretSet, 2)
				require.Equal(t, "first", secretSet[0].Selector())
				require.Equal(t, "second", secretSet[1].Selector())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			secretSet, err := prv.GetSecretSet(t.Context(), tc.selector)

			tc.assert(t, err, secretSet)
		})
	}
}

func TestProviderGetSecretSetFailsForCertificateStore(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "certs.pem")
	writeCertificatePEMFile(t, path, "first")

	validator, err := validation.NewValidator()
	require.NoError(t, err)

	df := encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct))

	prv, err := newProvider(provider.Args{
		Config:         map[string]any{"path": path, "watch": false},
		Logger:         zerolog.Nop(),
		DecoderFactory: df,
		Observer:       mocks.NewChangeObserverMock(t),
	})
	require.NoError(t, err)

	require.NoError(t, prv.Start(t.Context()))

	t.Cleanup(func() {
		_ = prv.Stop(context.Background())
	})

	secretSet, err := prv.GetSecretSet(t.Context(), provider.Selector{})

	require.ErrorIs(t, err, provider.ErrUnsupportedOperation)
	require.Nil(t, secretSet)
}

func TestProviderGetCredentials(t *testing.T) {
	t.Parallel()

	prv := &pemProvider{}

	_, err := prv.GetCredentials(t.Context(), provider.Selector{})

	require.ErrorIs(t, err, provider.ErrUnsupportedOperation)
}

func TestProviderGetCertificateBundle(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "certs.pem")
	writeCertificatePEMFile(t, path, "first", "second")

	validator, err := validation.NewValidator()
	require.NoError(t, err)

	df := encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct))

	prv, err := newProvider(provider.Args{
		Config:         map[string]any{"path": path, "watch": false},
		Logger:         zerolog.Nop(),
		DecoderFactory: df,
		Observer:       mocks.NewChangeObserverMock(t),
	})
	require.NoError(t, err)

	require.NoError(t, prv.Start(t.Context()))

	t.Cleanup(func() {
		_ = prv.Stop(context.Background())
	})

	bundle, err := prv.GetCertificateBundle(t.Context(), provider.Selector{})

	require.NoError(t, err)
	require.NotNil(t, bundle)
	require.Empty(t, bundle.Selector())
	require.Len(t, bundle.Certificates(), 2)
	require.Equal(t, "first", bundle.Certificates()[0].Subject.CommonName)
	require.Equal(t, "second", bundle.Certificates()[1].Subject.CommonName)
}

func TestProviderGetCertificateBundleFailsForKeyStore(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "keys.pem")
	writePEMFile(t, path, "first")

	validator, err := validation.NewValidator()
	require.NoError(t, err)

	df := encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct))

	prv, err := newProvider(provider.Args{
		Config:         map[string]any{"path": path, "watch": false},
		Logger:         zerolog.Nop(),
		DecoderFactory: df,
		Observer:       mocks.NewChangeObserverMock(t),
	})
	require.NoError(t, err)

	require.NoError(t, prv.Start(t.Context()))

	t.Cleanup(func() {
		_ = prv.Stop(context.Background())
	})

	bundle, err := prv.GetCertificateBundle(t.Context(), provider.Selector{})

	require.ErrorIs(t, err, provider.ErrUnsupportedOperation)
	require.Nil(t, bundle)
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

func writeCertificatePEMFile(t *testing.T, path string, names ...string) {
	t.Helper()

	opts := make([]pemx.EntryOption, 0, len(names))
	for _, name := range names {
		ca, err := testsupport.NewRootCA(name, 24*time.Hour)
		require.NoError(t, err)

		opts = append(opts, pemx.WithX509Certificate(ca.Certificate))
	}

	data, err := pemx.BuildPEM(opts...)
	require.NoError(t, err)

	err = os.WriteFile(path, data, 0o600)
	require.NoError(t, err)
}
