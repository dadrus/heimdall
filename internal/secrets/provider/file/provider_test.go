// Copyright 2026 Dimitrij Drus
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package file

import (
	"context"
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
)

func TestLoadFile(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		path   func(t *testing.T) string
		assert func(t *testing.T, secrets map[string]provider.Secret, credentials map[string]provider.Credentials, err error)
	}{
		"loads string secrets and credentials from yaml file": {
			path: func(t *testing.T) string {
				t.Helper()

				path := filepath.Join(t.TempDir(), "secrets.yaml")
				content := `
api_token: secret
github:
  client_id: heimdall
  client_secret: super-secret
`

				err := os.WriteFile(path, []byte(content), 0o600)
				require.NoError(t, err)

				return path
			},
			assert: func(t *testing.T, secrets map[string]provider.Secret, credentials map[string]provider.Credentials, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, secrets, 1)
				require.Len(t, credentials, 1)

				secret, ok := secrets["api_token"].(provider.StringSecret)
				require.True(t, ok)
				require.Equal(t, "api_token", secret.Selector())
				require.Equal(t, provider.SecretKindString, secret.Kind())
				require.Equal(t, "secret", secret.Value())

				creds := credentials["github"]
				require.NotNil(t, creds)
				require.Equal(t, "github", creds.Selector())
				require.Equal(t, map[string]any{
					"client_id":     "heimdall",
					"client_secret": "super-secret",
				}, creds.Values())
			},
		},
		"loads string secrets and credentials from json file": {
			path: func(t *testing.T) string {
				t.Helper()

				path := filepath.Join(t.TempDir(), "secrets.yaml")
				content := `{
  "api_token": "secret",
  "github": {
    "client_id": "heimdall",
    "client_secret": "super-secret"
  }
}`

				err := os.WriteFile(path, []byte(content), 0o600)
				require.NoError(t, err)

				return path
			},
			assert: func(t *testing.T, secrets map[string]provider.Secret, credentials map[string]provider.Credentials, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, secrets, 1)
				require.Len(t, credentials, 1)

				secret, ok := secrets["api_token"].(provider.StringSecret)
				require.True(t, ok)
				require.Equal(t, "secret", secret.Value())

				creds := credentials["github"]
				require.NotNil(t, creds)
				require.Equal(t, map[string]any{
					"client_id":     "heimdall",
					"client_secret": "super-secret",
				}, creds.Values())
			},
		},
		"fails if file does not exist": {
			path: func(t *testing.T) string {
				t.Helper()

				return filepath.Join(t.TempDir(), "missing.yaml")
			},
			assert: func(t *testing.T, secrets map[string]provider.Secret, credentials map[string]provider.Credentials, err error) {
				t.Helper()

				require.Nil(t, secrets)
				require.Nil(t, credentials)
				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "failed opening secrets file")
			},
		},
		"fails if file cannot be parsed": {
			path: func(t *testing.T) string {
				t.Helper()

				path := filepath.Join(t.TempDir(), "secrets.yaml")
				content := `"api_token: ["`

				err := os.WriteFile(path, []byte(content), 0o600)
				require.NoError(t, err)

				return path
			},
			assert: func(t *testing.T, secrets map[string]provider.Secret, credentials map[string]provider.Credentials, err error) {
				t.Helper()

				require.Nil(t, secrets)
				require.Nil(t, credentials)
				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "failed parsing secrets file")
			},
		},
		"fails if decoded entries are invalid": {
			path: func(t *testing.T) string {
				t.Helper()

				path := filepath.Join(t.TempDir(), "secrets.yaml")
				content := `api_token: 42`

				err := os.WriteFile(path, []byte(content), 0o600)
				require.NoError(t, err)

				return path
			},
			assert: func(t *testing.T, secrets map[string]provider.Secret, credentials map[string]provider.Credentials, err error) {
				t.Helper()

				require.Nil(t, secrets)
				require.Nil(t, credentials)
				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "must be either string or structured object")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			secrets, credentials, err := loadFile(tc.path(t))
			tc.assert(t, secrets, credentials, err)
		})
	}
}

func TestNewProvider(t *testing.T) {
	t.Parallel()

	secretsFile := filepath.Join(t.TempDir(), "secrets.yaml")

	for uc, tc := range map[string]struct {
		conf   map[string]any
		assert func(t *testing.T, err error, prv *fileProvider)
	}{
		"creates provider": {
			conf: map[string]any{"path": secretsFile},
			assert: func(t *testing.T, err error, prv *fileProvider) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, providerType, prv.Type())
				assert.Empty(t, prv.Dependencies())
				assert.False(t, prv.IsNamespaceAware())
				assert.Nil(t, prv.watcher)
				assert.Equal(t, secretsFile, prv.file)
			},
		},
		"creates provider with watch enabled": {
			conf: map[string]any{"path": secretsFile, "watch": true},
			assert: func(t *testing.T, err error, prv *fileProvider) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, providerType, prv.Type())
				assert.Empty(t, prv.Dependencies())
				assert.False(t, prv.IsNamespaceAware())
				assert.NotNil(t, prv.watcher)
				assert.Equal(t, secretsFile, prv.file)
			},
		},
		"fails for invalid watch field": {
			conf: map[string]any{"path": secretsFile, "watch": "yes"},
			assert: func(t *testing.T, err error, _ *fileProvider) {
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

			var fPrv *fileProvider
			if err == nil {
				fPrv = prv.(*fileProvider)
			}

			tc.assert(t, err, fPrv)
		})
	}
}

func TestProviderStart(t *testing.T) {
	t.Parallel()

	secretsFile := filepath.Join(t.TempDir(), "secrets.yaml")
	require.NoError(t, os.WriteFile(secretsFile, []byte(`my_secret: very_secret`), 0o600))

	for uc, tc := range map[string]struct {
		conf   map[string]any
		assert func(t *testing.T, err error, prv *fileProvider)
	}{
		"fails loading secrets file": {
			conf: map[string]any{"path": filepath.Join(t.TempDir(), "missing.yaml")},
			assert: func(t *testing.T, err error, prv *fileProvider) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "failed opening secrets file")
			},
		},
		"successfully loads secrets file and starts without watching for changes": {
			conf: map[string]any{"path": secretsFile, "watch": false},
			assert: func(t *testing.T, err error, prv *fileProvider) {
				t.Helper()

				require.NoError(t, err)
				assert.Empty(t, prv.credentials)
				assert.Len(t, prv.secrets, 1)
				assert.Nil(t, prv.watcher)
			},
		},
		"successfully loads secrets file and starts with watching for changes": {
			conf: map[string]any{"path": secretsFile, "watch": true},
			assert: func(t *testing.T, err error, prv *fileProvider) {
				t.Helper()

				require.NoError(t, err)
				assert.Empty(t, prv.credentials)
				assert.Len(t, prv.secrets, 1)
				assert.NotNil(t, prv.watcher)
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

			tc.assert(t, err, prv.(*fileProvider))
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

				path := filepath.Join(t.TempDir(), "secrets.yaml")
				require.NoError(t, os.WriteFile(path, []byte(`api_token: first`), 0o600))

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
				require.NoError(t, os.WriteFile(path, []byte(`api_token: second`), 0o600))

				require.Eventually(t, func() bool {
					secret, err := prv.GetSecret(t.Context(), provider.Selector{Value: "api_token"})
					if err != nil {
						return false
					}

					stringSecret, ok := secret.(provider.StringSecret)

					return ok && stringSecret.Value() == "second"
				}, time.Second, 20*time.Millisecond)
			},
		},
		"reloads source on atomic symlink update and emits source event": {
			path: func(t *testing.T) string {
				t.Helper()

				dir := t.TempDir()
				target := filepath.Join(dir, "secrets-1.yaml")
				require.NoError(t, os.WriteFile(target, []byte(`api_token: first`), 0o600))

				path := filepath.Join(dir, "secrets.yaml")
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
				oldTarget := filepath.Join(dir, "secrets-1.yaml")
				newTarget := filepath.Join(dir, "secrets-2.yaml")
				require.NoError(t, os.WriteFile(newTarget, []byte(`api_token: second`), 0o600))
				require.NoError(t, os.Remove(path))
				require.NoError(t, os.Symlink(newTarget, path))
				require.NoError(t, os.Chmod(oldTarget, 0o644))

				require.Eventually(t, func() bool {
					secret, err := prv.GetSecret(t.Context(), provider.Selector{Value: "api_token"})
					if err != nil {
						return false
					}

					stringSecret, ok := secret.(provider.StringSecret)

					return ok && stringSecret.Value() == "second"
				}, time.Second, 20*time.Millisecond)
			},
		},
		"keeps last-known-good secrets if reload fails": {
			path: func(t *testing.T) string {
				t.Helper()

				path := filepath.Join(t.TempDir(), "secrets.yaml")
				require.NoError(t, os.WriteFile(path, []byte(`api_token: first`), 0o600))

				return path
			},
			setup: func(t *testing.T, _ *mocks.ChangeObserverMock) { t.Helper() },
			action: func(t *testing.T, prv provider.Provider, path string) {
				t.Helper()
				t.Cleanup(func() { require.NoError(t, prv.Stop(context.Background())) })

				require.NoError(t, prv.Start(t.Context()))
				require.NoError(t, os.WriteFile(path, []byte(`api_token: 42`), 0o600))

				secret, err := prv.GetSecret(t.Context(), provider.Selector{Value: "api_token"})
				require.NoError(t, err)

				stringSecret, ok := secret.(provider.StringSecret)
				require.True(t, ok)
				require.Equal(t, "first", stringSecret.Value())
			},
		},
		"keeps last-known-good secrets if file is gone": {
			path: func(t *testing.T) string {
				t.Helper()

				path := filepath.Join(t.TempDir(), "secrets.yaml")
				require.NoError(t, os.WriteFile(path, []byte(`api_token: first`), 0o600))

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

				secret, err := prv.GetSecret(t.Context(), provider.Selector{Value: "api_token"})
				require.NoError(t, err)

				stringSecret, ok := secret.(provider.StringSecret)
				require.True(t, ok)
				require.Equal(t, "first", stringSecret.Value())
			},
		},
		"watcher is detached from startup context": {
			path: func(t *testing.T) string {
				t.Helper()

				path := filepath.Join(t.TempDir(), "secrets.yaml")
				require.NoError(t, os.WriteFile(path, []byte(`api_token: first`), 0o600))

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

				require.NoError(t, os.WriteFile(path, []byte(`api_token: second`), 0o600))

				require.Eventually(t, func() bool {
					secret, err := prv.GetSecret(t.Context(), provider.Selector{Value: "api_token"})
					if err != nil {
						return false
					}

					stringSecret, ok := secret.(provider.StringSecret)

					return ok && stringSecret.Value() == "second"
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

	path := filepath.Join(t.TempDir(), "secrets.yaml")
	content := `
api_token: secret
github:
  client_id: heimdall
  client_secret: secret
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

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
		"no secret for selector": {
			selector: provider.Selector{Value: "github"},
			assert: func(t *testing.T, err error, _ provider.Secret) {
				t.Helper()

				require.ErrorIs(t, err, provider.ErrSecretNotFound)
				require.ErrorContains(t, err, "selector 'github'")
			},
		},
		"successful": {
			selector: provider.Selector{Value: "api_token"},
			assert: func(t *testing.T, err error, secret provider.Secret) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, secret)
				assert.Equal(t, "api_token", secret.Selector())
				assert.Equal(t, provider.SecretKindString, secret.Kind())

				stringSecret, ok := secret.(provider.StringSecret)
				require.True(t, ok)
				require.Equal(t, "secret", stringSecret.Value())
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

func TestProviderGetSecretSet(t *testing.T) {
	t.Parallel()

	prv := &fileProvider{}

	_, err := prv.GetSecretSet(t.Context(), provider.Selector{})

	require.ErrorIs(t, err, provider.ErrUnsupportedOperation)
}

func TestProviderGetCredentials(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "secrets.yaml")
	content := `
api_token: secret
github:
  client_id: heimdall
  client_secret: secret
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

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
		assert   func(t *testing.T, err error, secret provider.Credentials)
	}{
		"no secret for selector": {
			selector: provider.Selector{Value: "api_token"},
			assert: func(t *testing.T, err error, _ provider.Credentials) {
				t.Helper()

				require.ErrorIs(t, err, provider.ErrCredentialsNotFound)
				require.ErrorContains(t, err, "selector 'api_token'")
			},
		},
		"successful": {
			selector: provider.Selector{Value: "github"},
			assert: func(t *testing.T, err error, creds provider.Credentials) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, creds)
				assert.Equal(t, "github", creds.Selector())

				require.Equal(t, map[string]any{"client_id": "heimdall", "client_secret": "secret"}, creds.Values())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			creds, err := prv.GetCredentials(t.Context(), tc.selector)

			tc.assert(t, err, creds)
		})
	}
}

func TestProviderGetCertificateBundle(t *testing.T) {
	t.Parallel()

	prv := &fileProvider{}

	_, err := prv.GetCertificateBundle(t.Context(), provider.Selector{})

	require.ErrorIs(t, err, provider.ErrUnsupportedOperation)
}
