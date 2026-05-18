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
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/cache/types"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/encoding"
	keyregistrymocks "github.com/dadrus/heimdall/internal/keyregistry/mocks"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets"
	secretsmocks "github.com/dadrus/heimdall/internal/secrets/mocks"
	secrettypes "github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/x/pkix/pemx"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestStandaloneCache(t *testing.T) {
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
		config     func(t *testing.T, sm *secretsmocks.ManagerMock, kr *keyregistrymocks.RegistryMock) []byte
		assert     func(t *testing.T, err error, cch types.Cache)
	}{
		"empty config": {
			config: func(t *testing.T, _ *secretsmocks.ManagerMock, _ *keyregistrymocks.RegistryMock) []byte {
				t.Helper()

				return []byte(``)
			},
			assert: func(t *testing.T, err error, _ types.Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "'address' is a required field")
			},
		},
		"empty address provided": {
			config: func(t *testing.T, _ *secretsmocks.ManagerMock, _ *keyregistrymocks.RegistryMock) []byte {
				t.Helper()

				return []byte(`address: ""`)
			},
			assert: func(t *testing.T, err error, _ types.Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "'address' is a required field")
			},
		},
		"config contains unsupported properties": {
			config: func(t *testing.T, _ *secretsmocks.ManagerMock, _ *keyregistrymocks.RegistryMock) []byte {
				t.Helper()

				return []byte(`foo: bar`)
			},
			assert: func(t *testing.T, err error, _ types.Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed decoding redis cache config")
			},
		},
		"not existing address provided": {
			config: func(t *testing.T, _ *secretsmocks.ManagerMock, _ *keyregistrymocks.RegistryMock) []byte {
				t.Helper()

				return []byte(`address: "foo.local:12345"`)
			},
			assert: func(t *testing.T, err error, _ types.Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrInternal)
				require.ErrorContains(t, err, "failed creating redis client")
			},
		},
		"successful cache creation without TLS and without credentials": {
			config: func(t *testing.T, _ *secretsmocks.ManagerMock, _ *keyregistrymocks.RegistryMock) []byte {
				t.Helper()

				db := miniredis.RunT(t)

				return []byte("{address: " + db.Addr() + ", client_cache: {disabled: true}, tls: {disabled: true}}")
			},
			assert: func(t *testing.T, err error, cch types.Cache) {
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
		"successful cache creation without TLS but with credentials": {
			config: func(t *testing.T, sm *secretsmocks.ManagerMock, _ *keyregistrymocks.RegistryMock) []byte {
				t.Helper()

				db := miniredis.RunT(t)

				secret := secrettypes.NewCredentials( "foo", map[string]any{
					"password": "foo",
				})

				sm.EXPECT().
					ResolveCredentials(mock.Anything, secrets.InternalRef("creds", "redis")).
					Return(secret, nil)
				sm.EXPECT().
					Subscribe(secrets.InternalRef("creds", "redis"), mock.Anything).
					Return(func() {}, nil)

				return []byte("{address: " + db.Addr() + ", client_cache: {disabled: true}, tls: {disabled: true}, credentials: {source: creds, selector: redis}}")
			},
			assert: func(t *testing.T, err error, cch types.Cache) {
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
		"cache creation fails due to failing credentials resolution": {
			config: func(t *testing.T, sm *secretsmocks.ManagerMock, _ *keyregistrymocks.RegistryMock) []byte {
				t.Helper()

				sm.EXPECT().
					ResolveCredentials(mock.Anything, secrets.InternalRef("creds", "redis")).
					Return(nil, assert.AnError)

				return []byte("{address: 127.0.0.1:12345, client_cache: {disabled: true}, tls: {disabled: true}, credentials: { source: creds, selector: redis }}")
			},
			assert: func(t *testing.T, err error, _ types.Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "failed resolving redis credentials")
			},
		},
		"with failing TLS config": {
			config: func(t *testing.T, sm *secretsmocks.ManagerMock, _ *keyregistrymocks.RegistryMock) []byte {
				t.Helper()

				sm.EXPECT().
					ResolveSecret(mock.Anything, secrets.InternalRef("redis", "tls")).
					Return(nil, assert.AnError)

				return []byte(`{ tls: { secret: { source: redis, selector: tls } }, address: "foo.local:12345"}`)
			},
			assert: func(t *testing.T, err error, _ types.Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "failed resolving TLS secret")
			},
		},
		"with TLS enforced, but disabled": {
			enforceTLS: true,
			config: func(t *testing.T, _ *secretsmocks.ManagerMock, _ *keyregistrymocks.RegistryMock) []byte {
				t.Helper()

				return []byte(
					`{address: "foo.local:12345", tls: { disabled: true} }`,
				)
			},
			assert: func(t *testing.T, err error, _ types.Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "'tls'.'disabled' must be false")
			},
		},
		"successful cache creation with TLS and credentials": {
			config: func(t *testing.T, sm *secretsmocks.ManagerMock, _ *keyregistrymocks.RegistryMock) []byte {
				t.Helper()

				rootCertPool = x509.NewCertPool()
				rootCertPool.AddCert(cert)

				cfg := &tls.Config{
					Certificates: []tls.Certificate{
						{PrivateKey: key, Leaf: cert, Certificate: [][]byte{cert.Raw}},
					},
					MinVersion: tls.VersionTLS13,
				}

				db := miniredis.NewMiniRedis()
				err = db.StartTLS(cfg)
				require.NoError(t, err)

				t.Cleanup(db.Close)

				secret := secrettypes.NewCredentials( "foo", map[string]any{
					"password": "foo",
				})

				sm.EXPECT().
					ResolveCredentials(mock.Anything, secrets.InternalRef("creds", "redis")).
					Return(secret, nil)
				sm.EXPECT().
					Subscribe(secrets.InternalRef("creds", "redis"), mock.Anything).
					Return(func() {}, nil)

				return []byte("{address: " + db.Addr() + ", client_cache: {disabled: true}, credentials: { source: creds, selector: redis }}")
			},
			assert: func(t *testing.T, err error, cch types.Cache) {
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
		"successful cache creation with mutual TLS": {
			config: func(t *testing.T, sm *secretsmocks.ManagerMock, kr *keyregistrymocks.RegistryMock) []byte {
				t.Helper()

				secret := secrettypes.NewAsymmetricKeySecret( "tls", "key1", key, []*x509.Certificate{cert})

				sm.EXPECT().
					ResolveSecret(mock.Anything, secrets.InternalRef("redis", "tls")).
					Return(secret, nil)
				sm.EXPECT().
					Subscribe(secrets.InternalRef("redis", "tls"), mock.Anything).
					Return(func() {}, nil)
				kr.EXPECT().Notify(mock.Anything)

				rootCertPool = x509.NewCertPool()
				rootCertPool.AddCert(cert)

				cfg := &tls.Config{
					Certificates: []tls.Certificate{
						{PrivateKey: key, Leaf: cert, Certificate: [][]byte{cert.Raw}},
					},
					MinVersion: tls.VersionTLS13,
					ClientCAs:  rootCertPool,
					ClientAuth: tls.RequireAndVerifyClientCert,
				}

				db := miniredis.NewMiniRedis()
				err = db.StartTLS(cfg)
				require.NoError(t, err)

				t.Cleanup(db.Close)

				return []byte("{address: " + db.Addr() + ", client_cache: {disabled: true}, tls: {secret: {source: redis, selector: tls}}}")
			},
			assert: func(t *testing.T, err error, cch types.Cache) {
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
			sm := secretsmocks.NewManagerMock(t)
			kr := keyregistrymocks.NewRegistryMock(t)
			es := config.EnforcementSettings{EnforceEgressTLS: tc.enforceTLS}

			validator, err := validation.NewValidator(
				validation.WithTagValidator(es),
				validation.WithErrorTranslator(es),
			)
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config(t, sm, kr))
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().DecoderFactory().
				Return(encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct)))
			appCtx.EXPECT().KeyRegistry().Maybe().Return(kr)
			appCtx.EXPECT().SecretsManager().Maybe().Return(sm)

			// WHEN
			cch, err := NewStandaloneCache(appCtx, conf)
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
