// Copyright 2024 Dimitrij Drus <dadrus@gmx.de>
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

package redis

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"testing"

	keyregistrymocks "github.com/dadrus/heimdall/internal/keyregistry/v2/mocks"
	secretsmocks "github.com/dadrus/heimdall/internal/secrets/mocks"
	secrettypes "github.com/dadrus/heimdall/internal/secrets/types"
	watchermocks "github.com/dadrus/heimdall/internal/watcher/mocks"
	"github.com/redis/rueidis"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/keyregistry/v2"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets"
)

func TestFileCredentialsReload(t *testing.T) {
	t.Parallel()

	// GIVEN
	testDir := t.TempDir()

	cf1, err := os.Create(filepath.Join(testDir, "credentials1.yaml"))
	require.NoError(t, err)

	_, err = cf1.WriteString(`
username: oof
password: rab
`)
	require.NoError(t, err)

	cf2, err := os.Create(filepath.Join(testDir, "credentials2.yaml"))
	require.NoError(t, err)

	_, err = cf2.WriteString(`
username: foo
password: bar
`)
	require.NoError(t, err)

	cf3, err := os.Create(filepath.Join(testDir, "credentials3.yaml"))
	require.NoError(t, err)

	_, err = cf3.WriteString(`
  foo: bar
  bar: foo
`)
	require.NoError(t, err)

	fc := &fileCredentials{Path: cf1.Name()}

	// WHEN
	err = fc.load()

	// THEN
	require.NoError(t, err)

	assert.Equal(t, "oof", fc.creds.Username)
	assert.Equal(t, "rab", fc.creds.Password)

	// WHEN
	fc.Path = cf2.Name()
	fc.OnChanged(log.Logger)

	// THEN
	assert.Equal(t, "foo", fc.creds.Username)
	assert.Equal(t, "bar", fc.creds.Password)

	// WHEN
	fc.Path = cf3.Name()
	fc.OnChanged(log.Logger)

	// THEN
	assert.Equal(t, "foo", fc.creds.Username)
	assert.Equal(t, "bar", fc.creds.Password)
}

func TestBaseConfigClientOptions(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	cert := &x509.Certificate{Raw: []byte("cert")}
	tlsSecret := secrettypes.NewAsymmetricKeySecret("redis", "tls", "kid", privateKey, []*x509.Certificate{cert})

	for uc, tc := range map[string]struct {
		cfg   baseConfig
		setup func(
			t *testing.T,
			watcher *watchermocks.WatcherMock,
			sm *secretsmocks.ManagerMock,
			observer *keyregistrymocks.RegistryMock,
		)
		assert func(t *testing.T, err error, opts rueidis.ClientOption)
	}{
		"registers external credentials with watcher": {
			cfg: baseConfig{
				TLS: tlsConfig{Disabled: true},
				Credentials: &fileCredentials{
					Path:  "/tmp/credentials.yaml",
					creds: &staticCredentials{Username: "foo", Password: "bar"},
				},
			},
			setup: func(t *testing.T, watcher *watchermocks.WatcherMock, _ *secretsmocks.ManagerMock, _ *keyregistrymocks.RegistryMock) {
				t.Helper()

				watcher.EXPECT().Add("/tmp/credentials.yaml", mock.Anything).Return(nil)
			},
			assert: func(t *testing.T, err error, opts rueidis.ClientOption) {
				t.Helper()

				require.NoError(t, err)

				creds, err := opts.AuthCredentialsFn(rueidis.AuthCredentialsContext{})
				require.NoError(t, err)

				assert.Equal(t, "foo", creds.Username)
				assert.Equal(t, "bar", creds.Password)
			},
		},
		"returns credentials watcher registration error": {
			cfg: baseConfig{
				TLS: tlsConfig{Disabled: true},
				Credentials: &fileCredentials{
					Path:  "/tmp/credentials.yaml",
					creds: &staticCredentials{Username: "foo", Password: "bar"},
				},
			},
			setup: func(t *testing.T, watcher *watchermocks.WatcherMock, _ *secretsmocks.ManagerMock, _ *keyregistrymocks.RegistryMock) {
				t.Helper()

				watcher.EXPECT().Add("/tmp/credentials.yaml", mock.Anything).Return(errors.New("boom"))
			},
			assert: func(t *testing.T, err error, _ rueidis.ClientOption) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "failed registering client credentials watcher")
			},
		},
		"fails if tls secret cannot be resolved": {
			cfg: baseConfig{
				TLS: tlsConfig{
					TLS: config.TLS{
						Secret: config.Secret{Source: "redis", Selector: "tls"},
					},
				},
			},
			setup: func(t *testing.T, _ *watchermocks.WatcherMock, sm *secretsmocks.ManagerMock, _ *keyregistrymocks.RegistryMock) {
				t.Helper()

				sm.EXPECT().
					ResolveSecret(mock.Anything, secrets.InternalRef("redis", "tls")).
					Return(nil, errors.New("boom"))
			},
			assert: func(t *testing.T, err error, _ rueidis.ClientOption) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed resolving TLS secret")
			},
		},
		"builds tls options for mutual tls": {
			cfg: baseConfig{
				TLS: tlsConfig{
					TLS: config.TLS{
						Secret: config.Secret{Source: "redis", Selector: "tls"},
					},
				},
			},
			setup: func(t *testing.T, _ *watchermocks.WatcherMock, sm *secretsmocks.ManagerMock, observer *keyregistrymocks.RegistryMock) {
				t.Helper()

				sm.EXPECT().
					ResolveSecret(mock.Anything, secrets.InternalRef("redis", "tls")).
					Return(tlsSecret, nil)
				sm.EXPECT().
					Subscribe(secrets.InternalRef("redis", "tls"), mock.Anything).
					Return(func() {}, nil)

				observer.EXPECT().Keys().Maybe().Return(nil)
				observer.EXPECT().
					Notify(mock.MatchedBy(func(ki keyregistry.KeyInfo) bool {
						return ki.Key.KeyID() == "kid" &&
							ki.Key.PrivateKey() == privateKey &&
							assert.ObjectsAreEqual(ki.Key.CertChain(), []*x509.Certificate{cert}) &&
							!ki.Exportable
					})).
					Return()
			},
			assert: func(t *testing.T, err error, opts rueidis.ClientOption) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, opts.DialCtxFn)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			watcher := watchermocks.NewWatcherMock(t)
			sm := secretsmocks.NewManagerMock(t)
			observer := keyregistrymocks.NewRegistryMock(t)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Watcher().Maybe().Return(watcher)
			appCtx.EXPECT().SecretsManager().Maybe().Return(sm)
			appCtx.EXPECT().KeyRegistry().Maybe().Return(observer)

			if tc.setup != nil {
				tc.setup(t, watcher, sm, observer)
			}

			opts, err := tc.cfg.clientOptions(appCtx)

			tc.assert(t, err, opts)
		})
	}
}
