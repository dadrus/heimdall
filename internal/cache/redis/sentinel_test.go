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
	"crypto/x509/pkix"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/x/pkix/pemx"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestSentinelCache(t *testing.T) {
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
		"no sentinel master set provided": {
			config: func(t *testing.T) []byte {
				t.Helper()

				return []byte(`nodes: ["foo:1234"]`)
			},
			assert: func(t *testing.T, err error, _ cache.Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'master' is a required field")
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

				return []byte(`{nodes: ["foo.local:12345"], master: foo}`)
			},
			assert: func(t *testing.T, err error, _ cache.Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				require.ErrorContains(t, err, "failed creating redis client")
			},
		},
		"with failing TLS config": {
			config: func(t *testing.T) []byte {
				t.Helper()

				return []byte(
					"{nodes: [ 'foo:1234' ], master: foo, client_cache: {disabled: true}, tls: { key_store: { path: /does/not/exist.pem } }}",
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
					"{nodes: [ 'foo:1234' ], master: foo, tls: { disabled: true }}",
				)
			},
			assert: func(t *testing.T, err error, _ cache.Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'tls'.'disabled' must be false")
			},
		},
		// successful tests are not possible with miniredis
		// Reasons: https://github.com/Bose/minisentinel does not support the SENTINELS subcommand
		// More importantly however is that miniredis does not support commands, like ROLE, which
		// are used by the client after resolving the replicas from the sentinel.
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			es := config.EnforcementSettings{EnforceEgressTLS: tc.enforceTLS}

			validator, err := validation.NewValidator(
				validation.WithTagValidator(es),
				validation.WithErrorTranslator(es),
			)
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config(t))
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Return(validator)
			appCtx.EXPECT().Watcher().Maybe().Return(nil)
			appCtx.EXPECT().CertificateObserver().Maybe().Return(nil)

			// WHEN
			cch, err := NewSentinelCache(appCtx, conf)
			if err == nil {
				err = cch.Start(context.TODO())
				if err == nil {
					defer cch.Stop(context.TODO())
				}
			}

			// THEN
			tc.assert(t, err, cch)
		})
	}
}
