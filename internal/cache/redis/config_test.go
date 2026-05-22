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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
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
	"github.com/dadrus/heimdall/internal/secrets/types"
)

func TestBaseConfigClientOptions(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	cert := &x509.Certificate{Raw: []byte("cert")}
	tlsSecret := types.NewAsymmetricKeySecret("tls", "kid", privateKey, []*x509.Certificate{cert})

	for uc, tc := range map[string]struct {
		cfg   baseConfig
		setup func(
			t *testing.T,
			sr *secretsmocks.ResolverMock,
			credentialsHandle *secretsmocks.CredentialsHandleMock,
			secretHandle *secretsmocks.SecretHandleMock,
			observer *keyregistrymocks.RegistryMock,
		)
		assert func(t *testing.T, err error, opts rueidis.ClientOption)
	}{
		"successfully resolves credentials": {
			cfg: baseConfig{
				TLS:         tlsConfig{Disabled: true},
				Credentials: &config.Secret{Source: "creds", Selector: "redis"},
			},
			setup: func(
				t *testing.T,
				sr *secretsmocks.ResolverMock,
				credentialsHandle *secretsmocks.CredentialsHandleMock,
				_ *secretsmocks.SecretHandleMock,
				_ *keyregistrymocks.RegistryMock,
			) {
				t.Helper()

				creds := types.NewCredentials("redis", map[string]any{
					"username": "foo",
					"password": "bar",
				})

				sr.EXPECT().
					Credentials(
						mock.Anything,
						secrets.Reference{Source: "creds", Selector: "redis"},
						mock.AnythingOfType("secrets2.ResolveOption"),
					).
					Return(credentialsHandle, nil)

				credentialsHandle.EXPECT().
					Get(mock.Anything).
					Return(creds, true)
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
			setup: func(
				t *testing.T,
				sr *secretsmocks.ResolverMock,
				_ *secretsmocks.CredentialsHandleMock,
				_ *secretsmocks.SecretHandleMock,
				_ *keyregistrymocks.RegistryMock,
			) {
				t.Helper()

				sr.EXPECT().
					Credentials(
						mock.Anything,
						secrets.Reference{Source: "creds", Selector: "redis"},
						mock.AnythingOfType("secrets2.ResolveOption"),
					).
					Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, err error, _ rueidis.ClientOption) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "failed resolving redis credentials")
			},
		},
		"fails if credentials are not available": {
			cfg: baseConfig{
				TLS:         tlsConfig{Disabled: true},
				Credentials: &config.Secret{Source: "creds", Selector: "redis"},
			},
			setup: func(
				t *testing.T,
				sr *secretsmocks.ResolverMock,
				credentialsHandle *secretsmocks.CredentialsHandleMock,
				_ *secretsmocks.SecretHandleMock,
				_ *keyregistrymocks.RegistryMock,
			) {
				t.Helper()

				sr.EXPECT().
					Credentials(
						mock.Anything,
						secrets.Reference{Source: "creds", Selector: "redis"},
						mock.AnythingOfType("secrets2.ResolveOption"),
					).
					Return(credentialsHandle, nil)

				credentialsHandle.EXPECT().
					Get(mock.Anything).
					Return(nil, false)
			},
			assert: func(t *testing.T, err error, opts rueidis.ClientOption) {
				t.Helper()

				require.NoError(t, err)

				creds, err := opts.AuthCredentialsFn(rueidis.AuthCredentialsContext{})

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "redis credentials are not available")
				require.Empty(t, creds)
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
			setup: func(
				t *testing.T,
				sr *secretsmocks.ResolverMock,
				_ *secretsmocks.CredentialsHandleMock,
				_ *secretsmocks.SecretHandleMock,
				_ *keyregistrymocks.RegistryMock,
			) {
				t.Helper()

				sr.EXPECT().
					Secret(
						mock.Anything,
						secrets.Reference{Source: "redis", Selector: "tls"},
						mock.AnythingOfType("secrets2.ResolveOption"),
					).
					Return(nil, assert.AnError)
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
			setup: func(
				t *testing.T,
				sr *secretsmocks.ResolverMock,
				_ *secretsmocks.CredentialsHandleMock,
				secretHandle *secretsmocks.SecretHandleMock,
				observer *keyregistrymocks.RegistryMock,
			) {
				t.Helper()

				sr.EXPECT().
					Secret(
						mock.Anything,
						secrets.Reference{Source: "redis", Selector: "tls"},
						mock.AnythingOfType("secrets2.ResolveOption"),
					).
					Return(secretHandle, nil)

				observer.EXPECT().Keys().Maybe().Return(nil)
				observer.EXPECT().
					Notify(mock.MatchedBy(func(ki keyregistry.KeyInfo) bool {
						return ki.Key.KeyID() == "kid" &&
							ki.Key.PrivateKey() == privateKey &&
							assert.ObjectsAreEqual(ki.Key.CertChain(), []*x509.Certificate{cert}) &&
							!ki.Exportable
					})).
					Return()

				secretHandle.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Secret]) bool {
						err := cb(context.Background(), tlsSecret)
						require.NoError(t, err)

						return true
					}))
			},
			assert: func(t *testing.T, err error, opts rueidis.ClientOption) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, opts.DialCtxFn)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			sr := secretsmocks.NewResolverMock(t)
			credentialsHandle := secretsmocks.NewCredentialsHandleMock(t)
			secretHandle := secretsmocks.NewSecretHandleMock(t)
			observer := keyregistrymocks.NewRegistryMock(t)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().SecretResolver().Maybe().Return(sr)
			appCtx.EXPECT().KeyRegistry().Maybe().Return(observer)

			if tc.setup != nil {
				tc.setup(t, sr, credentialsHandle, secretHandle, observer)
			}

			opts, err := tc.cfg.clientOptions(appCtx)

			tc.assert(t, err, opts)
		})
	}
}
