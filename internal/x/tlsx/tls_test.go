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

package tlsx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	mocks2 "github.com/dadrus/heimdall/internal/otel/metrics/certificate/mocks"
	"github.com/dadrus/heimdall/internal/watcher/mocks"
	"github.com/dadrus/heimdall/internal/x/pkix/pemx"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestToTLSConfig(t *testing.T) {
	t.Parallel()

	testDir := t.TempDir()

	privKey1, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	privKey2, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	cert, err := testsupport.NewCertificateBuilder(testsupport.WithValidity(time.Now(), 10*time.Hour),
		testsupport.WithSerialNumber(big.NewInt(1)),
		testsupport.WithSubject(pkix.Name{
			CommonName:   "test cert",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithSubjectPubKey(&privKey1.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithSelfSigned(),
		testsupport.WithSignaturePrivKey(privKey1)).
		Build()
	require.NoError(t, err)

	pemBytes, err := pemx.BuildPEM(
		pemx.WithECDSAPrivateKey(privKey1, pemx.WithHeader("X-Key-ID", "key1")),
		pemx.WithX509Certificate(cert),
		pemx.WithECDSAPrivateKey(privKey2, pemx.WithHeader("X-Key-ID", "key2")),
	)
	require.NoError(t, err)

	pemFile, err := os.Create(filepath.Join(testDir, "keystore.pem"))
	require.NoError(t, err)

	_, err = pemFile.Write(pemBytes)
	require.NoError(t, err)

	for uc, tc := range map[string]struct {
		conf       func(t *testing.T, wm *mocks.WatcherMock, co *mocks2.ObserverMock) config.TLS
		serverAuth bool
		clientAuth bool
		assert     func(t *testing.T, err error, conf *tls.Config)
	}{
		"empty config": {
			conf: func(t *testing.T, _ *mocks.WatcherMock, _ *mocks2.ObserverMock) config.TLS {
				t.Helper()

				return config.TLS{}
			},
			assert: func(t *testing.T, err error, conf *tls.Config) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, conf)

				assert.Empty(t, conf.Certificates)
				assert.Equal(t, uint16(tls.VersionTLS13), conf.MinVersion)
				assert.Len(t, conf.NextProtos, 2)
				assert.Contains(t, conf.NextProtos, "h2")
				assert.Contains(t, conf.NextProtos, "http/1.1")
			},
		},
		"empty config, but requires server auth": {
			serverAuth: true,
			conf: func(t *testing.T, _ *mocks.WatcherMock, _ *mocks2.ObserverMock) config.TLS {
				t.Helper()

				return config.TLS{}
			},
			assert: func(t *testing.T, err error, _ *tls.Config) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "no path to tls key")
			},
		},
		"fails due to not existent key store for TLS usage": {
			serverAuth: true,
			conf: func(t *testing.T, _ *mocks.WatcherMock, _ *mocks2.ObserverMock) config.TLS {
				t.Helper()

				return config.TLS{KeyStore: config.KeyStore{Path: "/no/such/file"}}
			},
			assert: func(t *testing.T, err error, _ *tls.Config) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed loading")
			},
		},
		"fails due to not existent key for the given key id for TLS usage": {
			serverAuth: true,
			conf: func(t *testing.T, _ *mocks.WatcherMock, _ *mocks2.ObserverMock) config.TLS {
				t.Helper()

				return config.TLS{
					KeyStore:   config.KeyStore{Path: pemFile.Name()},
					KeyID:      "foo",
					MinVersion: tls.VersionTLS12,
				}
			},
			assert: func(t *testing.T, err error, _ *tls.Config) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no such key")
			},
		},
		"fails due to not present certificates for the given key id": {
			serverAuth: true,
			conf: func(t *testing.T, _ *mocks.WatcherMock, _ *mocks2.ObserverMock) config.TLS {
				t.Helper()

				return config.TLS{
					KeyStore:   config.KeyStore{Path: pemFile.Name()},
					KeyID:      "key2",
					MinVersion: tls.VersionTLS12,
				}
			},
			assert: func(t *testing.T, err error, _ *tls.Config) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no certificate present")
			},
		},
		"fails due to failing watcher registration": {
			serverAuth: true,
			conf: func(t *testing.T, wm *mocks.WatcherMock, _ *mocks2.ObserverMock) config.TLS {
				t.Helper()

				wm.EXPECT().Add(mock.Anything, mock.Anything).Return(errors.New("test error"))

				return config.TLS{
					KeyStore:   config.KeyStore{Path: pemFile.Name()},
					MinVersion: tls.VersionTLS12,
				}
			},
			assert: func(t *testing.T, err error, _ *tls.Config) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, err.Error(), "test error")
			},
		},
		"successful with default key for TLS server auth": {
			serverAuth: true,
			conf: func(t *testing.T, wm *mocks.WatcherMock, co *mocks2.ObserverMock) config.TLS {
				t.Helper()

				wm.EXPECT().Add(mock.Anything, mock.Anything).Return(nil)
				co.EXPECT().Add(mock.MatchedBy(func(sup *certificateSupplier) bool {
					assert.Equal(t, "test", sup.Name())

					certs := sup.Certificates()
					assert.Len(t, certs, 1)
					assert.Equal(t, cert, certs[0])

					return true
				}))

				return config.TLS{
					KeyStore:   config.KeyStore{Path: pemFile.Name()},
					MinVersion: tls.VersionTLS12,
				}
			},
			assert: func(t *testing.T, err error, conf *tls.Config) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, conf)

				assert.NotNil(t, conf.GetCertificate)
				assert.Equal(t, uint16(tls.VersionTLS12), conf.MinVersion)
				assert.Len(t, conf.NextProtos, 2)
				assert.Contains(t, conf.NextProtos, "h2")
				assert.Contains(t, conf.NextProtos, "http/1.1")
			},
		},
		"successful with default key for TLS client auth": {
			clientAuth: true,
			conf: func(t *testing.T, wm *mocks.WatcherMock, co *mocks2.ObserverMock) config.TLS {
				t.Helper()

				wm.EXPECT().Add(mock.Anything, mock.Anything).Return(nil)
				co.EXPECT().Add(mock.MatchedBy(func(sup *certificateSupplier) bool {
					assert.Equal(t, "test", sup.Name())

					certs := sup.Certificates()
					assert.Len(t, certs, 1)
					assert.Equal(t, cert, certs[0])

					return true
				}))

				return config.TLS{
					KeyStore:   config.KeyStore{Path: pemFile.Name()},
					MinVersion: tls.VersionTLS12,
				}
			},
			assert: func(t *testing.T, err error, conf *tls.Config) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, conf)

				assert.NotNil(t, conf.GetClientCertificate)
				assert.Equal(t, uint16(tls.VersionTLS12), conf.MinVersion)
				assert.Len(t, conf.NextProtos, 2)
				assert.Contains(t, conf.NextProtos, "h2")
				assert.Contains(t, conf.NextProtos, "http/1.1")
			},
		},
		"successful with specified key id for TLS server auth": {
			serverAuth: true,
			conf: func(t *testing.T, wm *mocks.WatcherMock, co *mocks2.ObserverMock) config.TLS {
				t.Helper()

				wm.EXPECT().Add(mock.Anything, mock.Anything).Return(nil)
				co.EXPECT().Add(mock.MatchedBy(func(sup *certificateSupplier) bool {
					assert.Equal(t, "test", sup.Name())

					certs := sup.Certificates()
					assert.Len(t, certs, 1)
					assert.Equal(t, cert, certs[0])

					return true
				}))

				return config.TLS{
					KeyStore:   config.KeyStore{Path: pemFile.Name()},
					KeyID:      "key1",
					MinVersion: tls.VersionTLS12,
				}
			},
			assert: func(t *testing.T, err error, conf *tls.Config) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, conf)

				assert.NotNil(t, conf.GetCertificate)
				assert.Equal(t, uint16(tls.VersionTLS12), conf.MinVersion)
				assert.Len(t, conf.NextProtos, 2)
				assert.Contains(t, conf.NextProtos, "h2")
				assert.Contains(t, conf.NextProtos, "http/1.1")
			},
		},
		"successful with specified key id for TLS client auth": {
			clientAuth: true,
			conf: func(t *testing.T, wm *mocks.WatcherMock, co *mocks2.ObserverMock) config.TLS {
				t.Helper()

				wm.EXPECT().Add(mock.Anything, mock.Anything).Return(nil)
				co.EXPECT().Add(mock.MatchedBy(func(sup *certificateSupplier) bool {
					assert.Equal(t, "test", sup.Name())

					certs := sup.Certificates()
					assert.Len(t, certs, 1)
					assert.Equal(t, cert, certs[0])

					return true
				}))

				return config.TLS{
					KeyStore:   config.KeyStore{Path: pemFile.Name()},
					KeyID:      "key1",
					MinVersion: tls.VersionTLS12,
				}
			},
			assert: func(t *testing.T, err error, conf *tls.Config) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, conf)

				assert.NotNil(t, conf.GetClientCertificate)
				assert.Equal(t, uint16(tls.VersionTLS12), conf.MinVersion)
				assert.Len(t, conf.NextProtos, 2)
				assert.Contains(t, conf.NextProtos, "h2")
				assert.Contains(t, conf.NextProtos, "http/1.1")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// WHEN
			wm := mocks.NewWatcherMock(t)
			om := mocks2.NewObserverMock(t)

			tlsCfg := tc.conf(t, wm, om)

			conf, err := ToTLSConfig(
				&tlsCfg,
				WithServerAuthentication(tc.serverAuth),
				WithClientAuthentication(tc.clientAuth),
				WithSecretsWatcher(wm),
				WithCertificateObserver("test", om),
			)

			// THEN
			tc.assert(t, err, conf)
		})
	}
}
