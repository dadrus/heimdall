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
	"testing"

	"github.com/redis/rueidis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/keyregistry"
	keyregistrymocks "github.com/dadrus/heimdall/internal/keyregistry/mocks"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets"
	secretsmocks "github.com/dadrus/heimdall/internal/secrets/mocks"
	secrettypes "github.com/dadrus/heimdall/internal/secrets/types"
)

func TestBaseConfigClientOptions(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	cert := &x509.Certificate{Raw: []byte("cert")}
	tlsSecret := secrettypes.NewAsymmetricKeySecret("redis", "tls", "kid", privateKey, []*x509.Certificate{cert})

	for uc, tc := range map[string]struct {
		cfg   baseConfig
		setup func(
			t *testing.T,
			sm *secretsmocks.ManagerMock,
			observer *keyregistrymocks.RegistryMock,
		)
		assert func(t *testing.T, err error, opts rueidis.ClientOption)
	}{
		"successfully resolves credentials": {
			cfg: baseConfig{
				TLS:         tlsConfig{Disabled: true},
				Credentials: &config.Secret{Source: "creds", Selector: "redis"},
			},
			setup: func(t *testing.T, sm *secretsmocks.ManagerMock, _ *keyregistrymocks.RegistryMock) {
				t.Helper()

				secret := secrettypes.NewCredentials("inline", "foo", map[string]any{
					"username": "foo",
					"password": "bar",
				})

				sm.EXPECT().
					ResolveCredentials(mock.Anything, secrets.InternalRef("creds", "redis")).
					Return(secret, nil)
				sm.EXPECT().
					Subscribe(secrets.InternalRef("creds", "redis"), mock.Anything).
					Return(func() {}, nil)
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
		"fails to resolve credentials": {
			cfg: baseConfig{
				TLS:         tlsConfig{Disabled: true},
				Credentials: &config.Secret{Source: "creds", Selector: "redis"},
			},
			setup: func(t *testing.T, sm *secretsmocks.ManagerMock, _ *keyregistrymocks.RegistryMock) {
				t.Helper()

				sm.EXPECT().
					ResolveCredentials(mock.Anything, secrets.InternalRef("creds", "redis")).
					Return(nil, errors.New("boom"))
			},
			assert: func(t *testing.T, err error, _ rueidis.ClientOption) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "failed resolving redis credentials")
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
			setup: func(t *testing.T, sm *secretsmocks.ManagerMock, _ *keyregistrymocks.RegistryMock) {
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
			setup: func(t *testing.T, sm *secretsmocks.ManagerMock, observer *keyregistrymocks.RegistryMock) {
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
			sm := secretsmocks.NewManagerMock(t)
			observer := keyregistrymocks.NewRegistryMock(t)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().SecretsManager().Maybe().Return(sm)
			appCtx.EXPECT().KeyRegistry().Maybe().Return(observer)

			if tc.setup != nil {
				tc.setup(t, sm, observer)
			}

			opts, err := tc.cfg.clientOptions(appCtx)

			tc.assert(t, err, opts)
		})
	}
}
