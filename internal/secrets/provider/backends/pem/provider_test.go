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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog"
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
		createPath func(t *testing.T) string
		setup      func(t *testing.T, om *mocks.ChangeObserverMock)
		action     func(t *testing.T, prv provider.Provider, path string)
	}{
		"does nothing if watch is disabled": {
			setup: func(t *testing.T, _ *mocks.ChangeObserverMock) {
				t.Helper()
			},
			action: func(t *testing.T, prv provider.Provider, _ string) {
				t.Helper()

				require.NoError(t, prv.Start(context.Background()))
				require.NoError(t, prv.Stop(context.Background()))
			},
		},
		"returns error if watch target cannot be resolved": {
			setup: func(t *testing.T, _ *mocks.ChangeObserverMock) {
				t.Helper()
			},
			action: func(t *testing.T, prv provider.Provider, path string) {
				t.Helper()

				require.NoError(t, os.Remove(path))

				err := prv.Start(context.Background())
				require.Error(t, err)
				require.ErrorContains(t, err, "failed to resolve pem provider watch path")
			},
		},
		"reloads source on file change and emits source event": {
			setup: func(t *testing.T, om *mocks.ChangeObserverMock) {
				t.Helper()

				om.EXPECT().
					Notify(mock.MatchedBy(func(e provider.ChangeEvent) bool {
						return len(e.Selectors) == 0
					}))
			},
			action: func(t *testing.T, prv provider.Provider, path string) {
				t.Helper()

				t.Cleanup(func() {
					_ = prv.Stop(context.Background())
				})

				require.NoError(t, prv.Start(context.Background()))

				writePEMFile(t, path, "second")

				require.Eventually(t, func() bool {
					secret, err := prv.GetSecret(context.Background(), provider.Selector{})
					if err != nil {
						return false
					}

					return secret.Selector() == "second"
				}, time.Second, 20*time.Millisecond)
			},
		},
		"reloads source on atomic symlink update and emits source event": {
			createPath: func(t *testing.T) string {
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

				om.EXPECT().
					Notify(mock.MatchedBy(func(e provider.ChangeEvent) bool {
						return len(e.Selectors) == 0
					}))
			},
			action: func(t *testing.T, prv provider.Provider, path string) {
				t.Helper()

				t.Cleanup(func() {
					_ = prv.Stop(context.Background())
				})

				require.NoError(t, prv.Start(context.Background()))

				dir := filepath.Dir(path)

				oldTarget := filepath.Join(dir, "keys-1.pem")
				newTarget := filepath.Join(dir, "keys-2.pem")
				writePEMFile(t, newTarget, "second")

				require.NoError(t, os.Remove(path))
				require.NoError(t, os.Symlink(newTarget, path))

				require.NoError(t, os.Chmod(oldTarget, 0o644))

				require.Eventually(t, func() bool {
					secret, err := prv.GetSecret(context.Background(), provider.Selector{})
					if err != nil {
						return false
					}

					return secret.Selector() == "second"
				}, time.Second, 20*time.Millisecond)
			},
		},
		"keeps last-known-good key material if reload fails": {
			setup: func(t *testing.T, _ *mocks.ChangeObserverMock) {
				t.Helper()
			},
			action: func(t *testing.T, prv provider.Provider, path string) {
				t.Helper()

				t.Cleanup(func() {
					_ = prv.Stop(context.Background())
				})

				require.NoError(t, prv.Start(context.Background()))

				require.NoError(t, os.WriteFile(path, []byte("not a pem file"), 0o600))

				secret, err := prv.GetSecret(context.Background(), provider.Selector{})
				require.NoError(t, err)
				require.Equal(t, "first", secret.Selector())
			},
		},
		"watcher is detached from startup context": {
			setup: func(t *testing.T, om *mocks.ChangeObserverMock) {
				t.Helper()

				om.EXPECT().
					Notify(mock.MatchedBy(func(e provider.ChangeEvent) bool {
						return len(e.Selectors) == 0
					}))
			},
			action: func(t *testing.T, prv provider.Provider, path string) {
				t.Helper()

				t.Cleanup(func() {
					_ = prv.Stop(context.Background())
				})

				startCtx, cancelStart := context.WithCancel(context.Background())

				require.NoError(t, prv.Start(startCtx))

				cancelStart()

				writePEMFile(t, path, "second")

				require.Eventually(t, func() bool {
					secret, err := prv.GetSecret(context.Background(), provider.Selector{})
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

			pemFile := createPEMFile(t, "first")
			if tc.createPath != nil {
				pemFile = tc.createPath(t)
			}

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

func TestProviderUpdateWatchForAtomicUpdate(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, dir string) (path string, resolvedPath string)
		update func(t *testing.T, path string)
		assert func(t *testing.T, prv *pemProvider, logs *bytes.Buffer, changed bool)
	}{
		"returns false if resolved path did not change": {
			setup: func(t *testing.T, dir string) (string, string) {
				t.Helper()

				target := filepath.Join(dir, "keys-1.pem")
				writePEMFile(t, target, "first")

				path := filepath.Join(dir, "keys.pem")
				require.NoError(t, os.Symlink(target, path))

				resolvedPath, err := filepath.EvalSymlinks(path)
				require.NoError(t, err)

				return path, resolvedPath
			},
			update: func(t *testing.T, _ string) {
				t.Helper()
			},
			assert: func(t *testing.T, prv *pemProvider, _ *bytes.Buffer, changed bool) {
				t.Helper()

				require.False(t, changed)

				resolvedPath, err := filepath.EvalSymlinks(prv.path)
				require.NoError(t, err)
				require.Equal(t, resolvedPath, prv.resolvedPath)
			},
		},
		"returns true and updates resolved path if symlink target changed": {
			setup: func(t *testing.T, dir string) (string, string) {
				t.Helper()

				target := filepath.Join(dir, "keys-1.pem")
				writePEMFile(t, target, "first")

				path := filepath.Join(dir, "keys.pem")
				require.NoError(t, os.Symlink(target, path))

				resolvedPath, err := filepath.EvalSymlinks(path)
				require.NoError(t, err)

				return path, resolvedPath
			},
			update: func(t *testing.T, path string) {
				t.Helper()

				target := filepath.Join(filepath.Dir(path), "keys-2.pem")
				writePEMFile(t, target, "second")

				require.NoError(t, os.Remove(path))
				require.NoError(t, os.Symlink(target, path))
			},
			assert: func(t *testing.T, prv *pemProvider, _ *bytes.Buffer, changed bool) {
				t.Helper()

				require.True(t, changed)

				resolvedPath, err := filepath.EvalSymlinks(prv.path)
				require.NoError(t, err)
				require.Equal(t, resolvedPath, prv.resolvedPath)
			},
		},
		"returns false if watched path disappeared": {
			setup: func(t *testing.T, dir string) (string, string) {
				t.Helper()

				path := filepath.Join(dir, "keys.pem")
				writePEMFile(t, path, "first")

				resolvedPath, err := filepath.EvalSymlinks(path)
				require.NoError(t, err)

				return path, resolvedPath
			},
			update: func(t *testing.T, path string) {
				t.Helper()

				require.NoError(t, os.Remove(path))
			},
			assert: func(t *testing.T, _ *pemProvider, _ *bytes.Buffer, changed bool) {
				t.Helper()

				require.False(t, changed)
			},
		},
		"returns false if symlink target disappeared": {
			setup: func(t *testing.T, dir string) (string, string) {
				t.Helper()

				target := filepath.Join(dir, "keys-1.pem")
				writePEMFile(t, target, "first")

				path := filepath.Join(dir, "keys.pem")
				require.NoError(t, os.Symlink(target, path))

				resolvedPath, err := filepath.EvalSymlinks(path)
				require.NoError(t, err)

				return path, resolvedPath
			},
			update: func(t *testing.T, path string) {
				t.Helper()

				require.NoError(t, os.Remove(path))
				require.NoError(t, os.Symlink(filepath.Join(filepath.Dir(path), "missing.pem"), path))
			},
			assert: func(t *testing.T, _ *pemProvider, logs *bytes.Buffer, changed bool) {
				t.Helper()

				require.False(t, changed)
				require.Empty(t, logs.String())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()

			path, resolvedPath := tc.setup(t, dir)

			watcher, err := fsnotify.NewWatcher()
			require.NoError(t, err)

			t.Cleanup(func() {
				_ = watcher.Close()
			})

			require.NoError(t, watcher.Add(path))

			var logs bytes.Buffer

			prv := &pemProvider{
				path:         path,
				resolvedPath: resolvedPath,
				logger:       zerolog.New(&logs),
			}

			tc.update(t, path)

			changed := prv.updateWatchForAtomicUpdate(watcher, path)

			tc.assert(t, prv, &logs, changed)
		})
	}
}

func TestProviderReload(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, path string, om *mocks.ChangeObserverMock)
		assert func(t *testing.T, prv *pemProvider, logs *bytes.Buffer)
	}{
		"reloads key material and emits source event": {
			setup: func(t *testing.T, path string, om *mocks.ChangeObserverMock) {
				t.Helper()

				writePEMFile(t, path, "second")

				om.EXPECT().
					Notify(mock.MatchedBy(func(e provider.ChangeEvent) bool {
						return len(e.Selectors) == 0
					}))
			},
			assert: func(t *testing.T, prv *pemProvider, logs *bytes.Buffer) {
				t.Helper()

				prv.mu.RLock()
				ks := prv.ks
				prv.mu.RUnlock()

				require.Len(t, ks, 1)
				require.Equal(t, "second", ks[0].Selector())
				require.Contains(t, logs.String(), "pem file reloaded")
			},
		},
		"keeps last-known-good key material and logs if reload fails": {
			setup: func(t *testing.T, path string, _ *mocks.ChangeObserverMock) {
				t.Helper()

				require.NoError(t, os.WriteFile(path, []byte("not a pem file"), 0o600))
			},
			assert: func(t *testing.T, prv *pemProvider, logs *bytes.Buffer) {
				t.Helper()

				prv.mu.RLock()
				ks := prv.ks
				prv.mu.RUnlock()

				require.Len(t, ks, 1)
				require.Equal(t, "first", ks[0].Selector())
				require.Contains(t, logs.String(), "Reloading pem file failed")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			path := createPEMFile(t, "first")
			ks, err := newKeyStoreFromPEMFile(path, "")
			require.NoError(t, err)

			var logs bytes.Buffer

			om := mocks.NewChangeObserverMock(t)
			tc.setup(t, path, om)

			prv := &pemProvider{
				path:     path,
				logger:   zerolog.New(&logs),
				observer: om,
				ks:       ks,
			}

			prv.reload()

			tc.assert(t, prv, &logs)
		})
	}
}

func TestIsReloadEvent(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		event fsnotify.Event
		want  bool
	}{
		"write reloads": {
			event: fsnotify.Event{Op: fsnotify.Write},
			want:  true,
		},
		"create reloads": {
			event: fsnotify.Event{Op: fsnotify.Create},
			want:  true,
		},
		"rename reloads": {
			event: fsnotify.Event{Op: fsnotify.Rename},
			want:  true,
		},
		"chmod does not directly reload": {
			event: fsnotify.Event{Op: fsnotify.Chmod},
		},
		"remove does not reload": {
			event: fsnotify.Event{Op: fsnotify.Remove},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tc.want, isReloadEvent(tc.event))
		})
	}
}

func TestIsAtomicUpdateEvent(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		event fsnotify.Event
		want  bool
	}{
		"chmod is atomic update event": {
			event: fsnotify.Event{Op: fsnotify.Chmod},
			want:  true,
		},
		"write is not atomic update event": {
			event: fsnotify.Event{Op: fsnotify.Write},
		},
		"rename is not atomic update event": {
			event: fsnotify.Event{Op: fsnotify.Rename},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tc.want, isAtomicUpdateEvent(tc.event))
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
				require.Equal(t, "first", secret.Selector())
			},
		},
		"returns matching secret for explicit selector": {
			provider: newPEMProviderForTest(t, "first", "second"),
			selector: provider.Selector{Value: "second"},
			assert: func(t *testing.T, err error, secret types.Secret) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, "second", secret.Selector())
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

			secret, err := tc.provider.GetSecret(t.Context(), tc.selector)

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
				require.Equal(t, []string{"first", "second"}, selectorsFromSecretSet(secretSet))
			},
		},
		"returns all secrets regardless of selector": {
			provider: newPEMProviderForTest(t, "first", "second"),
			selector: provider.Selector{Value: "ignored"},
			assert: func(t *testing.T, err error, secretSet []types.Secret) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, secretSet, 2)
				require.Equal(t, []string{"first", "second"}, selectorsFromSecretSet(secretSet))
			},
		},
		"returns empty set if key store is empty": {
			provider: &pemProvider{},
			assert: func(t *testing.T, err error, secretSet []types.Secret) {
				t.Helper()

				require.NoError(t, err)
				require.Empty(t, secretSet)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			secretSet, err := tc.provider.GetSecretSet(t.Context(), tc.selector)

			tc.assert(t, err, secretSet)
		})
	}
}

func TestProviderGetCredentials(t *testing.T) {
	t.Parallel()

	prov := &pemProvider{}

	_, err := prov.GetCredentials(t.Context(), provider.Selector{})

	require.ErrorIs(t, err, types.ErrUnsupportedOperation)
}

func TestProviderGetCertificateBundle(t *testing.T) {
	t.Parallel()

	prov := &pemProvider{}

	_, err := prov.GetCertificateBundle(t.Context(), provider.Selector{})

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
