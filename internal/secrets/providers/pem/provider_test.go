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
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/secrets/registry"
	"github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/x/pkix/pemx"
)

func TestNewProvider(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		conf   func(*testing.T) (*app.ContextMock, map[string]any)
		assert func(*testing.T, types.Provider, error)
	}{
		"successfully creates provider": {
			conf: func(t *testing.T) (*app.ContextMock, map[string]any) {
				t.Helper()

				return newAppContext(t), map[string]any{"path": createPEMFile(t, "first", "second")}
			},
			assert: func(t *testing.T, provider types.Provider, err error) {
				t.Helper()
				require.NoError(t, err)
				require.Equal(t, "tls", provider.Name())
				require.Equal(t, "pem", provider.Type())
			},
		},
		"fails for missing path config": {
			conf: func(t *testing.T) (*app.ContextMock, map[string]any) {
				t.Helper()

				return newAppContext(t), map[string]any{}
			},
			assert: func(t *testing.T, _ types.Provider, err error) {
				t.Helper()
				require.Error(t, err)
				require.ErrorContains(t, err, "path")
			},
		},
		"fails for invalid watch field": {
			conf: func(t *testing.T) (*app.ContextMock, map[string]any) {
				t.Helper()

				return newAppContext(t), map[string]any{
					"path":  createPEMFile(t, "first"),
					"watch": "yes",
				}
			},
			assert: func(t *testing.T, _ types.Provider, err error) {
				t.Helper()
				require.Error(t, err)
				require.ErrorContains(t, err, "watch")
			},
		},
		"fails for invalid path": {
			conf: func(t *testing.T) (*app.ContextMock, map[string]any) {
				t.Helper()

				return newAppContext(t), map[string]any{
					"path": "does_not_exist.pem",
				}
			},
			assert: func(t *testing.T, _ types.Provider, err error) {
				t.Helper()
				require.Error(t, err)
				require.ErrorContains(t, err, "does_not_exist.pem")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			appCtx, conf := tc.conf(t)
			prv, err := newProvider(appCtx, "tls", conf)
			tc.assert(t, prv, err)
		})
	}
}

func TestProviderWatch(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		conf   func(*testing.T) (map[string]any, string)
		action func(*testing.T, types.Provider, string)
	}{
		"returns error if callback is nil": {
			conf: func(t *testing.T) (map[string]any, string) {
				t.Helper()

				path := createPEMFile(t, "first")

				return map[string]any{
					"path":  path,
					"watch": true,
				}, path
			},
			action: func(t *testing.T, provider types.Provider, _ string) {
				t.Helper()

				err := provider.Start(context.Background(), nil)
				require.Error(t, err)
				require.ErrorContains(t, err, "must not be nil")
			},
		},
		"reloads source on file change and emits source event": {
			conf: func(t *testing.T) (map[string]any, string) {
				t.Helper()

				path := createPEMFile(t, "first")

				return map[string]any{
					"path":  path,
					"watch": true,
				}, path
			},
			action: func(t *testing.T, provider types.Provider, path string) {
				t.Helper()

				changes := make(chan types.ChangeEvent, 2)
				err := provider.Start(context.Background(), func(event types.ChangeEvent) {
					changes <- event
				})
				require.NoError(t, err)
				t.Cleanup(func() { _ = provider.Stop(context.Background()) })

				writePEMFile(t, path, "second")

				select {
				case evt := <-changes:
					require.Equal(t, "tls", evt.Source)
					require.Empty(t, evt.Refs)
				case <-time.After(500 * time.Millisecond):
					t.Fatal("watch callback was not called")
				}

				secret, err := provider.ResolveSecret(context.Background(), "")
				require.NoError(t, err)
				require.Equal(t, "second", secret.KeyID)
			},
		},
		"keeps last-known-good key material if reload fails": {
			conf: func(t *testing.T) (map[string]any, string) {
				t.Helper()
				path := createPEMFile(t, "first")

				return map[string]any{
					"path":  path,
					"watch": true,
				}, path
			},
			action: func(t *testing.T, provider types.Provider, path string) {
				t.Helper()

				changes := make(chan types.ChangeEvent, 2)

				err := provider.Start(context.Background(), func(event types.ChangeEvent) {
					changes <- event
				})
				require.NoError(t, err)
				t.Cleanup(func() { _ = provider.Stop(context.Background()) })

				err = os.WriteFile(path, []byte("not a pem file"), 0o600)
				require.NoError(t, err)

				select {
				case <-changes:
					t.Fatal("unexpected change event on failed reload")
				case <-time.After(200 * time.Millisecond):
				}

				secret, err := provider.ResolveSecret(context.Background(), "")
				require.NoError(t, err)
				require.Equal(t, "first", secret.KeyID)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			appCtx := newAppContext(t)
			conf, path := tc.conf(t)
			provider, err := registry.Create(appCtx, "pem", "tls", conf)
			require.NoError(t, err)

			tc.action(t, provider, path)
		})
	}
}

func createPEMFile(t *testing.T, keyIDs ...string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "keys.pem")
	writePEMFile(t, path, keyIDs...)

	return path
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

func newAppContext(t *testing.T) *app.ContextMock {
	t.Helper()

	validator, err := validation.NewValidator()
	require.NoError(t, err)

	appCtx := app.NewContextMock(t)
	appCtx.EXPECT().Validator().Return(validator).Maybe()
	appCtx.EXPECT().Logger().Return(zerolog.Nop()).Maybe()

	return appCtx
}
