// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
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

package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/pkix/pemx"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestTLSMinVersionOrDefault(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc       string
		version  TLSMinVersion
		expected uint16
	}{
		{uc: "not configured", expected: tls.VersionTLS13},
		{uc: "configured", version: tls.VersionTLS12, expected: tls.VersionTLS12},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.version.OrDefault())
		})
	}
}

func TestTLSCipherSuitesOrDefault(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc       string
		suites   TLSCipherSuites
		expected []uint16
	}{
		{
			uc: "not configured",
			expected: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
		},
		{
			uc:     "configured",
			suites: TLSCipherSuites{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			expected: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.suites.OrDefault())
		})
	}
}

func TestTLSConfig(t *testing.T) {
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

	for _, tc := range []struct {
		uc     string
		conf   TLS
		assert func(t *testing.T, err error, conf *tls.Config)
	}{
		{
			uc: "empty config",
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
		{
			uc:   "fails due to not existent key store for TLS usage",
			conf: TLS{KeyStore: KeyStore{Path: "/no/such/file"}},
			assert: func(t *testing.T, err error, _ *tls.Config) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed loading")
			},
		},
		{
			uc: "fails due to not existent key for the given key id for TLS usage",
			conf: TLS{
				KeyStore:   KeyStore{Path: pemFile.Name()},
				KeyID:      "foo",
				MinVersion: tls.VersionTLS12,
			},
			assert: func(t *testing.T, err error, _ *tls.Config) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no such key")
			},
		},
		{
			uc: "fails due to not present certificates for the given key id",
			conf: TLS{
				KeyStore:   KeyStore{Path: pemFile.Name()},
				KeyID:      "key2",
				MinVersion: tls.VersionTLS12,
			},
			assert: func(t *testing.T, err error, _ *tls.Config) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no certificate present")
			},
		},
		{
			uc: "successful with default key",
			conf: TLS{
				KeyStore:   KeyStore{Path: pemFile.Name()},
				MinVersion: tls.VersionTLS12,
			},
			assert: func(t *testing.T, err error, conf *tls.Config) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, conf)

				assert.Len(t, conf.Certificates, 1)
				assert.Equal(t, cert, conf.Certificates[0].Leaf)
				assert.Equal(t, uint16(tls.VersionTLS12), conf.MinVersion)
				assert.Len(t, conf.NextProtos, 2)
				assert.Contains(t, conf.NextProtos, "h2")
				assert.Contains(t, conf.NextProtos, "http/1.1")
			},
		},
		{
			uc: "successful with specified key id",
			conf: TLS{
				KeyStore:   KeyStore{Path: pemFile.Name()},
				KeyID:      "key1",
				MinVersion: tls.VersionTLS12,
			},
			assert: func(t *testing.T, err error, conf *tls.Config) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, conf)

				assert.Len(t, conf.Certificates, 1)
				assert.Equal(t, cert, conf.Certificates[0].Leaf)
				assert.Equal(t, uint16(tls.VersionTLS12), conf.MinVersion)
				assert.Len(t, conf.NextProtos, 2)
				assert.Contains(t, conf.NextProtos, "h2")
				assert.Contains(t, conf.NextProtos, "http/1.1")
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// WHEN
			conf, err := tc.conf.TLSConfig()

			// THEN
			tc.assert(t, err, conf)
		})
	}
}
