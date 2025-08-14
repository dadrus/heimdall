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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/x/pkix/pemx"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestClusterCache(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	cert, err := testsupport.NewCertificateBuilder(
		testsupport.WithSerialNumber(big.NewInt(1)),
		testsupport.WithValidity(time.Now(), 10*time.Hour),
		testsupport.WithSubject(pkix.Name{
			CommonName:   "test cert",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithSubjectPubKey(&key.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithSignaturePrivKey(key),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature),
		testsupport.WithExtendedKeyUsage(x509.ExtKeyUsageServerAuth),
		testsupport.WithExtendedKeyUsage(x509.ExtKeyUsageClientAuth),
		testsupport.WithGeneratedSubjectKeyID(),
		testsupport.WithIPAddresses([]net.IP{net.ParseIP("127.0.0.1")}),
		testsupport.WithSelfSigned(),
	).Build()
	require.NoError(t, err)

	testDir := t.TempDir()

	pemBytes, err := pemx.BuildPEM(
		pemx.WithECDSAPrivateKey(key),
		pemx.WithX509Certificate(cert),
	)
	require.NoError(t, err)

	pemFile, err := os.Create(filepath.Join(testDir, "keystore.pem"))
	require.NoError(t, err)

	_, err = pemFile.Write(pemBytes)
	require.NoError(t, err)

	for uc, tc := range map[string]struct {
		enforceTLS bool
		config     func(t *testing.T) []byte
		assert     func(t *testing.T, err error, cch cache.Cache)
	}{
		"empty config": {
			config: func(t *testing.T) []byte {
				t.Helper()

				return []byte(``)
			},
			assert: func(t *testing.T, err error, _ cache.Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'nodes' must contain more than 0 items")
			},
		},
		"empty nodes config provided": {
			config: func(t *testing.T) []byte {
				t.Helper()

				return []byte(`nodes: [""]`)
			},
			assert: func(t *testing.T, err error, _ cache.Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'nodes'[0] is a required field")
			},
		},
		"config contains unsupported properties": {
			config: func(t *testing.T) []byte {
				t.Helper()

				return []byte(`foo: bar`)
			},
			assert: func(t *testing.T, err error, _ cache.Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed decoding redis cache config")
			},
		},
		"not existing address provided": {
			config: func(t *testing.T) []byte {
				t.Helper()

				return []byte(`nodes: ["foo.local:12345"]`)
			},
			assert: func(t *testing.T, err error, _ cache.Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				require.ErrorContains(t, err, "failed creating redis client")
			},
		},
		"successful cache creation without TLS": {
			config: func(t *testing.T) []byte {
				t.Helper()

				db1 := miniredis.RunT(t)
				db2 := miniredis.RunT(t)

				return []byte(fmt.Sprintf(
					"{nodes: [ '%s', '%s' ], client_cache: {disabled: true}, tls: {disabled: true}}",
					db1.Addr(), db2.Addr(),
				))
			},
			assert: func(t *testing.T, err error, cch cache.Cache) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, cch)

				err = cch.Set(t.Context(), "foo", []byte("bar"), 1*time.Second)
				require.NoError(t, err)

				data, err := cch.Get(t.Context(), "foo")
				require.NoError(t, err)

				require.Equal(t, []byte("bar"), data)
			},
		},
		"with failing TLS config": {
			config: func(t *testing.T) []byte {
				t.Helper()

				return []byte(
					"{nodes: [ 'foo:1234' ], client_cache: {disabled: true}, tls: { key_store: { path: /does/not/exist.pem } }}",
				)
			},
			assert: func(t *testing.T, err error, _ cache.Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				require.ErrorContains(t, err, "failed loading keystore")
			},
		},
		"with TLS enforced, but disabled": {
			enforceTLS: true,
			config: func(t *testing.T) []byte {
				t.Helper()

				return []byte(
					"{nodes: [ 'foo:1234' ], client_cache: {disabled: true}, tls: { disabled: true} }",
				)
			},
			assert: func(t *testing.T, err error, _ cache.Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'tls'.'disabled' must be false")
			},
		},
		"successful cache creation with TLS": {
			config: func(t *testing.T) []byte {
				t.Helper()

				rootCertPool = x509.NewCertPool()
				rootCertPool.AddCert(cert)

				cfg := &tls.Config{
					Certificates: []tls.Certificate{
						{PrivateKey: key, Leaf: cert, Certificate: [][]byte{cert.Raw}},
					},
					MinVersion: tls.VersionTLS13,
				}

				db1 := miniredis.NewMiniRedis()
				err = db1.StartTLS(cfg)
				require.NoError(t, err)

				db2 := miniredis.NewMiniRedis()
				err = db2.StartTLS(cfg)
				require.NoError(t, err)

				t.Cleanup(db1.Close)

				return []byte(fmt.Sprintf(
					"{nodes: [ '%s', '%s' ], client_cache: {disabled: true}}",
					db1.Addr(), db2.Addr()),
				)
			},
			assert: func(t *testing.T, err error, cch cache.Cache) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, cch)

				err = cch.Set(t.Context(), "foo", []byte("bar"), 1*time.Second)
				require.NoError(t, err)

				data, err := cch.Get(t.Context(), "foo")
				require.NoError(t, err)

				require.Equal(t, []byte("bar"), data)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			conf, err := testsupport.DecodeTestConfig(tc.config(t))
			require.NoError(t, err)

			es := config.EnforcementSettings{EnforceEgressTLS: tc.enforceTLS}

			validator, err := validation.NewValidator(
				validation.WithTagValidator(es),
				validation.WithErrorTranslator(es),
			)
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Return(validator)
			appCtx.EXPECT().Watcher().Maybe().Return(nil)
			appCtx.EXPECT().CertificateObserver().Maybe().Return(nil)

			// WHEN
			cch, err := NewClusterCache(appCtx, conf)
			if err == nil {
				err = cch.Start(t.Context())
				if err == nil {
					defer cch.Stop(t.Context())
				}
			}

			// THEN
			tc.assert(t, err, cch)
		})
	}
}
