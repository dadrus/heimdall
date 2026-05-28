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

package tlsx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets"
	secretsmocks "github.com/dadrus/heimdall/internal/secrets/mocks"
	"github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestToServerTLSConfig(t *testing.T) {
	t.Parallel()

	secret := newTLSSecret(t)

	for uc, tc := range map[string]struct {
		conf   config.TLS
		setup  func(t *testing.T, sr *secretsmocks.ResolverMock, handle *secretsmocks.SecretHandleMock)
		assert func(t *testing.T, err error, cfg *tls.Config)
	}{
		"fails if secret resolution fails": {
			conf: config.TLS{
				Secret: config.Secret{Source: "tls", Selector: "server"},
			},
			setup: func(
				t *testing.T,
				sr *secretsmocks.ResolverMock,
				_ *secretsmocks.SecretHandleMock,
			) {
				t.Helper()

				sr.EXPECT().
					Secret(secrets.Reference{Source: "tls", Selector: "server"}).
					Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, err error, cfg *tls.Config) {
				t.Helper()

				require.Nil(t, cfg)
				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorIs(t, err, assert.AnError)
				require.ErrorContains(t, err, "failed resolving TLS secret")
			},
		},
		"successful": {
			conf: config.TLS{
				Secret:     config.Secret{Source: "tls", Selector: "server"},
				MinVersion: tls.VersionTLS12,
			},
			setup: func(
				t *testing.T,
				sr *secretsmocks.ResolverMock,
				handle *secretsmocks.SecretHandleMock,
			) {
				t.Helper()

				sr.EXPECT().
					Secret(
						secrets.Reference{Source: "tls", Selector: "server"},
					).
					Return(handle, nil)

				handle.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Secret]) bool {
						err := cb(t.Context(), secret)
						require.NoError(t, err)

						return true
					}))
			},
			assert: func(t *testing.T, err error, cfg *tls.Config) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, cfg)
				require.NotNil(t, cfg.GetCertificate)
				require.Nil(t, cfg.GetClientCertificate)
				require.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
				require.NotEmpty(t, cfg.CipherSuites)
				require.Equal(t, []string{"h2", "http/1.1"}, cfg.NextProtos)
			},
		},
		"get certificate fails before first successful update": {
			conf: config.TLS{
				Secret: config.Secret{Source: "tls", Selector: "server"},
			},
			setup: func(
				t *testing.T,
				sr *secretsmocks.ResolverMock,
				handle *secretsmocks.SecretHandleMock,
			) {
				t.Helper()

				sr.EXPECT().
					Secret(secrets.Reference{Source: "tls", Selector: "server"}).
					Return(handle, nil)

				handle.EXPECT().
					OnUpdate(mock.Anything)
			},
			assert: func(t *testing.T, err error, cfg *tls.Config) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, cfg)
				require.NotNil(t, cfg.GetCertificate)

				cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
				require.Nil(t, cert)
				require.Error(t, err)
				require.ErrorIs(t, err, errNoCertificatePresent)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			sr := secretsmocks.NewResolverMock(t)
			handle := secretsmocks.NewSecretHandleMock(t)

			tc.setup(t, sr, handle)

			cfg, err := ToServerTLSConfig(sr, &tc.conf)

			tc.assert(t, err, cfg)
		})
	}
}

func TestToClientTLSConfig(t *testing.T) {
	t.Parallel()

	secret := newTLSSecret(t)

	for uc, tc := range map[string]struct {
		conf   config.TLS
		setup  func(t *testing.T, sr *secretsmocks.ResolverMock, handle *secretsmocks.SecretHandleMock)
		assert func(t *testing.T, err error, cfg *tls.Config)
	}{
		"without client certificate secret": {
			conf: config.TLS{},
			setup: func(
				t *testing.T,
				_ *secretsmocks.ResolverMock,
				_ *secretsmocks.SecretHandleMock,
			) {
				t.Helper()
			},
			assert: func(t *testing.T, err error, cfg *tls.Config) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, cfg)
				require.Nil(t, cfg.GetCertificate)
				require.Nil(t, cfg.GetClientCertificate)
				require.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
				require.Empty(t, cfg.CipherSuites)
				require.Equal(t, []string{"h2", "http/1.1"}, cfg.NextProtos)
			},
		},
		"fails if secret resolution fails": {
			conf: config.TLS{
				Secret: config.Secret{Source: "tls", Selector: "client"},
			},
			setup: func(
				t *testing.T,
				sr *secretsmocks.ResolverMock,
				_ *secretsmocks.SecretHandleMock,
			) {
				t.Helper()

				sr.EXPECT().
					Secret(secrets.Reference{Source: "tls", Selector: "client"}).
					Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, err error, cfg *tls.Config) {
				t.Helper()

				require.Nil(t, cfg)
				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorIs(t, err, assert.AnError)
				require.ErrorContains(t, err, "failed resolving TLS secret")
			},
		},
		"successful with client certificate secret": {
			conf: config.TLS{
				Secret: config.Secret{Source: "tls", Selector: "client"},
			},
			setup: func(
				t *testing.T,
				sr *secretsmocks.ResolverMock,
				handle *secretsmocks.SecretHandleMock,
			) {
				t.Helper()

				sr.EXPECT().
					Secret(secrets.Reference{Source: "tls", Selector: "client"}).
					Return(handle, nil)

				handle.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Secret]) bool {
						err := cb(t.Context(), secret)
						require.NoError(t, err)

						return true
					}))
			},
			assert: func(t *testing.T, err error, cfg *tls.Config) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, cfg)
				require.Nil(t, cfg.GetCertificate)
				require.NotNil(t, cfg.GetClientCertificate)
				require.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
				require.Empty(t, cfg.CipherSuites)
				require.Equal(t, []string{"h2", "http/1.1"}, cfg.NextProtos)
			},
		},
		"get client certificate fails before first successful update": {
			conf: config.TLS{
				Secret: config.Secret{Source: "tls", Selector: "client"},
			},
			setup: func(
				t *testing.T,
				sr *secretsmocks.ResolverMock,
				handle *secretsmocks.SecretHandleMock,
			) {
				t.Helper()

				sr.EXPECT().
					Secret(secrets.Reference{Source: "tls", Selector: "client"}).
					Return(handle, nil)

				handle.EXPECT().
					OnUpdate(mock.Anything)
			},
			assert: func(t *testing.T, err error, cfg *tls.Config) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, cfg)
				require.NotNil(t, cfg.GetClientCertificate)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			sr := secretsmocks.NewResolverMock(t)
			handle := secretsmocks.NewSecretHandleMock(t)

			tc.setup(t, sr, handle)

			cfg, err := ToClientTLSConfig(sr, &tc.conf)

			tc.assert(t, err, cfg)
		})
	}
}

func TestGetCertificate(t *testing.T) {
	t.Parallel()

	secret := newTLSSecret(t)

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, sr *secretsmocks.ResolverMock, handle *secretsmocks.SecretHandleMock, req *certificateRequestMock)
		assert func(t *testing.T, err error, cert *tls.Certificate)
	}{
		"fails if no certificate is available": {
			setup: func(
				t *testing.T,
				sr *secretsmocks.ResolverMock,
				handle *secretsmocks.SecretHandleMock,
				_ *certificateRequestMock,
			) {
				t.Helper()

				sr.EXPECT().
					Secret(secrets.Reference{Source: "tls", Selector: "server"}).
					Return(handle, nil)

				handle.EXPECT().
					OnUpdate(mock.Anything)
			},
			assert: func(t *testing.T, err error, cert *tls.Certificate) {
				t.Helper()

				require.Nil(t, cert)
				require.Error(t, err)
				require.ErrorIs(t, err, errNoCertificatePresent)
			},
		},
		"fails if certificate is incompatible": {
			setup: func(
				t *testing.T,
				sr *secretsmocks.ResolverMock,
				handle *secretsmocks.SecretHandleMock,
				req *certificateRequestMock,
			) {
				t.Helper()

				sr.EXPECT().
					Secret(secrets.Reference{Source: "tls", Selector: "server"}).
					Return(handle, nil)

				handle.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Secret]) bool {
						err := cb(t.Context(), secret)
						require.NoError(t, err)

						return true
					}))

				req.EXPECT().
					SupportsCertificate(mock.MatchedBy(func(cert *tls.Certificate) bool {
						return cert != nil &&
							cert.PrivateKey == secret.PrivateKey() &&
							cert.Leaf == secret.CertChain()[0]
					})).
					Return(assert.AnError)
			},
			assert: func(t *testing.T, err error, cert *tls.Certificate) {
				t.Helper()

				require.Nil(t, cert)
				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
			},
		},
		"returns cached certificate": {
			setup: func(
				t *testing.T,
				sr *secretsmocks.ResolverMock,
				handle *secretsmocks.SecretHandleMock,
				req *certificateRequestMock,
			) {
				t.Helper()

				sr.EXPECT().
					Secret(secrets.Reference{Source: "tls", Selector: "server"}).
					Return(handle, nil)

				handle.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Secret]) bool {
						err := cb(t.Context(), secret)
						require.NoError(t, err)

						return true
					}))

				req.EXPECT().
					SupportsCertificate(mock.MatchedBy(func(cert *tls.Certificate) bool {
						return cert != nil &&
							cert.PrivateKey == secret.PrivateKey() &&
							cert.Leaf == secret.CertChain()[0]
					})).
					Return(nil)
			},
			assert: func(t *testing.T, err error, cert *tls.Certificate) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, cert)
				require.NotNil(t, cert.PrivateKey)
				require.NotNil(t, cert.Leaf)
				require.Len(t, cert.Certificate, 1)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			sr := secretsmocks.NewResolverMock(t)
			handle := secretsmocks.NewSecretHandleMock(t)
			req := newCertificateRequestMock(t)

			tc.setup(t, sr, handle, req)

			informer, err := secrets.NewSecretInformer(
				sr,
				secrets.Reference{Source: "tls", Selector: "server"},
				secrets.WithConverter(toTLSCertificate),
			)
			require.NoError(t, err)

			cert, err := getCertificate(informer, req)

			tc.assert(t, err, cert)
		})
	}
}

func TestNewCertificateInformer(t *testing.T) {
	t.Parallel()

	secret := newTLSSecret(t)

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, sr *secretsmocks.ResolverMock, handle *secretsmocks.SecretHandleMock)
		assert func(t *testing.T, informer *secrets.SecretInformer[*tls.Certificate], err error)
	}{
		"wraps resolver error as configuration error": {
			setup: func(
				t *testing.T,
				sr *secretsmocks.ResolverMock,
				_ *secretsmocks.SecretHandleMock,
			) {
				t.Helper()

				sr.EXPECT().
					Secret(secrets.Reference{Source: "tls", Selector: "server"}).
					Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, informer *secrets.SecretInformer[*tls.Certificate], err error) {
				t.Helper()

				require.Nil(t, informer)
				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorIs(t, err, assert.AnError)
				require.ErrorContains(t, err, "failed resolving TLS secret")
			},
		},
		"creates informer and notifies key observer on update": {
			setup: func(
				t *testing.T,
				sr *secretsmocks.ResolverMock,
				handle *secretsmocks.SecretHandleMock,
			) {
				t.Helper()

				sr.EXPECT().
					Secret(secrets.Reference{Source: "tls", Selector: "server"}).
					Return(handle, nil)

				handle.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Secret]) bool {
						err := cb(t.Context(), secret)
						require.NoError(t, err)

						return true
					}))
			},
			assert: func(t *testing.T, informer *secrets.SecretInformer[*tls.Certificate], err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, informer)

				cert, ok := informer.Get()
				require.True(t, ok)
				require.NotNil(t, cert)
				require.NotNil(t, cert.PrivateKey)
				require.NotNil(t, cert.Leaf)
				require.Len(t, cert.Certificate, 1)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			sr := secretsmocks.NewResolverMock(t)
			handle := secretsmocks.NewSecretHandleMock(t)

			tc.setup(t, sr, handle)

			informer, err := newCertificateInformer(
				&config.TLS{
					Secret: config.Secret{Source: "tls", Selector: "server"},
				},
				sr,
			)

			tc.assert(t, informer, err)
		})
	}
}

func TestToTLSCertificate(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	rootCA, err := testsupport.NewRootCA("Test Root CA", 24*time.Hour)
	require.NoError(t, err)

	leaf, err := rootCA.IssueCertificate(
		testsupport.WithSubject(pkix.Name{CommonName: "leaf"}),
		testsupport.WithValidity(time.Now(), 12*time.Hour),
		testsupport.WithSubjectPubKey(&key.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature),
	)
	require.NoError(t, err)

	for uc, tc := range map[string]struct {
		secret secrets.Secret
		assert func(t *testing.T, err error, cert *tls.Certificate)
	}{
		"fails for wrong secret type": {
			secret: types.NewStringSecret("server", "key1"),
			assert: func(t *testing.T, err error, cert *tls.Certificate) {
				t.Helper()

				require.Nil(t, cert)
				require.Error(t, err)
				require.ErrorContains(t, err, "secret is not suitable for TLS")
			},
		},
		"fails without certificate chain": {
			secret: types.NewAsymmetricKeySecret("server", "key1", key, nil),
			assert: func(t *testing.T, err error, cert *tls.Certificate) {
				t.Helper()

				require.Nil(t, cert)
				require.Error(t, err)
				require.ErrorContains(t, err, "secret is not suitable for TLS")
			},
		},
		"creates tls certificate from full chain": {
			secret: types.NewAsymmetricKeySecret(
				"server",
				"key1",
				key,
				[]*x509.Certificate{leaf, rootCA.Certificate},
			),
			assert: func(t *testing.T, err error, cert *tls.Certificate) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, cert)
				require.Same(t, key, cert.PrivateKey)
				require.Same(t, leaf, cert.Leaf)
				require.Len(t, cert.Certificate, 2)
				require.Equal(t, leaf.Raw, cert.Certificate[0])
				require.Equal(t, rootCA.Certificate.Raw, cert.Certificate[1])
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			cert, err := toTLSCertificate(tc.secret)

			tc.assert(t, err, cert)
		})
	}
}

func TestServerTLSConfigGetCertificate(t *testing.T) {
	t.Parallel()

	secret := newTLSSecret(t)

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, sr *secretsmocks.ResolverMock, handle *secretsmocks.SecretHandleMock, req *tls.ClientHelloInfo)
		assert func(t *testing.T, cert *tls.Certificate, err error)
	}{
		"fails if no certificate is available": {
			setup: func(
				t *testing.T,
				sr *secretsmocks.ResolverMock,
				handle *secretsmocks.SecretHandleMock,
				_ *tls.ClientHelloInfo,
			) {
				t.Helper()

				sr.EXPECT().
					Secret(secrets.Reference{Source: "tls", Selector: "server"}).
					Return(handle, nil)

				handle.EXPECT().
					OnUpdate(mock.Anything)
			},
			assert: func(t *testing.T, cert *tls.Certificate, err error) {
				t.Helper()

				require.Nil(t, cert)
				require.Error(t, err)
				require.ErrorIs(t, err, errNoCertificatePresent)
			},
		},
		"fails if certificate is incompatible": {
			setup: func(
				t *testing.T,
				sr *secretsmocks.ResolverMock,
				handle *secretsmocks.SecretHandleMock,
				req *tls.ClientHelloInfo,
			) {
				t.Helper()

				sr.EXPECT().
					Secret(secrets.Reference{Source: "tls", Selector: "server"}).
					Return(handle, nil)

				handle.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Secret]) bool {
						err := cb(t.Context(), secret)
						require.NoError(t, err)

						return true
					}))

				req.SupportedVersions = []uint16{tls.VersionTLS12}
				req.SignatureSchemes = []tls.SignatureScheme{
					tls.PKCS1WithSHA256,
				}
				req.CipherSuites = []uint16{
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				}
			},
			assert: func(t *testing.T, cert *tls.Certificate, err error) {
				t.Helper()

				require.Nil(t, cert)
				require.Error(t, err)
			},
		},
		"returns cached certificate": {
			setup: func(
				t *testing.T,
				sr *secretsmocks.ResolverMock,
				handle *secretsmocks.SecretHandleMock,
				req *tls.ClientHelloInfo,
			) {
				t.Helper()

				sr.EXPECT().
					Secret(secrets.Reference{Source: "tls", Selector: "server"}).
					Return(handle, nil)

				handle.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Secret]) bool {
						err := cb(t.Context(), secret)
						require.NoError(t, err)

						return true
					}))

				req.SupportedVersions = []uint16{
					tls.VersionTLS13,
					tls.VersionTLS12,
				}
				req.SignatureSchemes = []tls.SignatureScheme{
					tls.ECDSAWithP384AndSHA384,
					tls.ECDSAWithP256AndSHA256,
					tls.ECDSAWithP521AndSHA512,
				}
				req.CipherSuites = []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				}
			},
			assert: func(t *testing.T, cert *tls.Certificate, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, cert)
				require.Same(t, secret.PrivateKey(), cert.PrivateKey)
				require.Same(t, secret.CertChain()[0], cert.Leaf)
				require.Len(t, cert.Certificate, 1)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			sr := secretsmocks.NewResolverMock(t)
			handle := secretsmocks.NewSecretHandleMock(t)
			req := &tls.ClientHelloInfo{}

			tc.setup(t, sr, handle, req)

			cfg, err := ToServerTLSConfig(
				sr,
				&config.TLS{
					Secret: config.Secret{Source: "tls", Selector: "server"},
				},
			)
			require.NoError(t, err)
			require.NotNil(t, cfg)
			require.NotNil(t, cfg.GetCertificate)

			cert, err := cfg.GetCertificate(req)

			tc.assert(t, cert, err)
		})
	}
}

func TestClientTLSConfigGetClientCertificate(t *testing.T) {
	t.Parallel()

	secret := newTLSSecret(t)

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, sr *secretsmocks.ResolverMock, handle *secretsmocks.SecretHandleMock, req *tls.CertificateRequestInfo)
		assert func(t *testing.T, cert *tls.Certificate, err error)
	}{
		"fails if no certificate is available": {
			setup: func(
				t *testing.T,
				sr *secretsmocks.ResolverMock,
				handle *secretsmocks.SecretHandleMock,
				_ *tls.CertificateRequestInfo,
			) {
				t.Helper()

				sr.EXPECT().
					Secret(secrets.Reference{Source: "tls", Selector: "client"}).
					Return(handle, nil)

				handle.EXPECT().
					OnUpdate(mock.Anything)
			},
			assert: func(t *testing.T, cert *tls.Certificate, err error) {
				t.Helper()

				require.Nil(t, cert)
				require.Error(t, err)
				require.ErrorIs(t, err, errNoCertificatePresent)
			},
		},
		"fails if certificate is incompatible": {
			setup: func(
				t *testing.T,
				sr *secretsmocks.ResolverMock,
				handle *secretsmocks.SecretHandleMock,
				req *tls.CertificateRequestInfo,
			) {
				t.Helper()

				sr.EXPECT().
					Secret(secrets.Reference{Source: "tls", Selector: "client"}).
					Return(handle, nil)

				handle.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Secret]) bool {
						err := cb(t.Context(), secret)
						require.NoError(t, err)

						return true
					}))

				req.Version = tls.VersionTLS12
				req.SignatureSchemes = []tls.SignatureScheme{
					tls.PKCS1WithSHA256,
				}
			},
			assert: func(t *testing.T, cert *tls.Certificate, err error) {
				t.Helper()

				require.Nil(t, cert)
				require.Error(t, err)
			},
		},
		"returns cached certificate": {
			setup: func(
				t *testing.T,
				sr *secretsmocks.ResolverMock,
				handle *secretsmocks.SecretHandleMock,
				req *tls.CertificateRequestInfo,
			) {
				t.Helper()

				sr.EXPECT().
					Secret(secrets.Reference{Source: "tls", Selector: "client"}).
					Return(handle, nil)

				handle.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Secret]) bool {
						err := cb(t.Context(), secret)
						require.NoError(t, err)

						return true
					}))

				req.Version = tls.VersionTLS13
				req.SignatureSchemes = []tls.SignatureScheme{
					tls.ECDSAWithP384AndSHA384,
					tls.ECDSAWithP256AndSHA256,
					tls.ECDSAWithP521AndSHA512,
				}
			},
			assert: func(t *testing.T, cert *tls.Certificate, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, cert)
				require.Same(t, secret.PrivateKey(), cert.PrivateKey)
				require.Same(t, secret.CertChain()[0], cert.Leaf)
				require.Len(t, cert.Certificate, 1)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			sr := secretsmocks.NewResolverMock(t)
			handle := secretsmocks.NewSecretHandleMock(t)
			req := &tls.CertificateRequestInfo{}

			tc.setup(t, sr, handle, req)

			cfg, err := ToClientTLSConfig(
				sr,
				&config.TLS{
					Secret: config.Secret{Source: "tls", Selector: "client"},
				},
			)
			require.NoError(t, err)
			require.NotNil(t, cfg)
			require.NotNil(t, cfg.GetClientCertificate)

			cert, err := cfg.GetClientCertificate(req)

			tc.assert(t, cert, err)
		})
	}
}

func newTLSSecret(t *testing.T) secrets.AsymmetricKeySecret {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	cert, err := testsupport.NewCertificateBuilder(
		testsupport.WithValidity(time.Now(), 12*time.Hour),
		testsupport.WithSerialNumber(big.NewInt(1)),
		testsupport.WithSubject(pkix.Name{
			CommonName:   "test cert",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithSubjectPubKey(&key.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithSelfSigned(),
		testsupport.WithSignaturePrivKey(key),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature),
	).Build()
	require.NoError(t, err)

	return types.NewAsymmetricKeySecret("server", "key1", key, []*x509.Certificate{cert})
}
