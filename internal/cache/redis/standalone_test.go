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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/watcher/mocks"
	"github.com/dadrus/heimdall/internal/x/pkix/pemx"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestNewStandaloneCache(t *testing.T) {
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

	for _, tc := range []struct {
		uc     string
		config func(t *testing.T, mock *mocks.WatcherMock) []byte
		assert func(t *testing.T, err error, cch cache.Cache)
	}{
		{
			uc: "empty config",
			config: func(t *testing.T, _ *mocks.WatcherMock) []byte {
				t.Helper()

				return []byte(``)
			},
			assert: func(t *testing.T, err error, _ cache.Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'address' is a required field")
			},
		},
		{
			uc: "empty address provided",
			config: func(t *testing.T, _ *mocks.WatcherMock) []byte {
				t.Helper()

				return []byte(`address: ""`)
			},
			assert: func(t *testing.T, err error, _ cache.Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'address' is a required field")
			},
		},
		{
			uc: "config contains unsupported properties",
			config: func(t *testing.T, _ *mocks.WatcherMock) []byte {
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
		{
			uc: "not existing address provided",
			config: func(t *testing.T, _ *mocks.WatcherMock) []byte {
				t.Helper()

				return []byte(`address: "foo.local:12345"`)
			},
			assert: func(t *testing.T, err error, _ cache.Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				require.ErrorContains(t, err, "failed creating redis client")
			},
		},
		{
			uc: "successful cache creation without TLS and without credentials",
			config: func(t *testing.T, _ *mocks.WatcherMock) []byte {
				t.Helper()

				db := miniredis.RunT(t)

				return []byte(fmt.Sprintf(
					"{address: %s, client_cache: {disabled: true}, tls: {disabled: true}}",
					db.Addr(),
				))
			},
			assert: func(t *testing.T, err error, cch cache.Cache) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, cch)

				err = cch.Set(context.TODO(), "foo", []byte("bar"), 1*time.Second)
				require.NoError(t, err)

				data, err := cch.Get(context.TODO(), "foo")
				require.NoError(t, err)

				require.Equal(t, []byte("bar"), data)
			},
		},
		{
			uc: "successful cache creation without TLS but with static credentials",
			config: func(t *testing.T, _ *mocks.WatcherMock) []byte {
				t.Helper()

				db := miniredis.RunT(t)

				return []byte(fmt.Sprintf(
					"{address: %s, client_cache: {disabled: true}, tls: {disabled: true}, credentials: {password: foo}}",
					db.Addr(),
				))
			},
			assert: func(t *testing.T, err error, cch cache.Cache) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, cch)

				err = cch.Set(context.TODO(), "foo", []byte("bar"), 1*time.Second)
				require.NoError(t, err)

				data, err := cch.Get(context.TODO(), "foo")
				require.NoError(t, err)

				require.Equal(t, []byte("bar"), data)
			},
		},
		{
			uc: "cache creation fails due to failing watcher registration for external credentials",
			config: func(t *testing.T, wm *mocks.WatcherMock) []byte {
				t.Helper()

				cf, err := os.Create(filepath.Join(testDir, "credentials.yaml"))
				require.NoError(t, err)

				_, err = cf.WriteString(`
  username: oof
  password: rab
`)
				require.NoError(t, err)

				wm.EXPECT().Add(cf.Name(), mock.Anything).Return(errors.New("test error"))

				return []byte(fmt.Sprintf(
					"{address: 127.0.0.1:12345, client_cache: {disabled: true}, tls: {disabled: true}, credentials: { path: %s }}",
					cf.Name(),
				))
			},
			assert: func(t *testing.T, err error, _ cache.Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "failed registering client credentials watcher")
			},
		},
		{
			uc: "with failing TLS config",
			config: func(t *testing.T, _ *mocks.WatcherMock) []byte {
				t.Helper()

				return []byte(`{ tls: { key_store: { path: /does/not/exist.pem } }, address: "foo.local:12345"}`)
			},
			assert: func(t *testing.T, err error, _ cache.Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				require.ErrorContains(t, err, "failed creating tls configuration")
			},
		},
		{
			uc: "successful cache creation with TLS and external credentials",
			config: func(t *testing.T, wm *mocks.WatcherMock) []byte {
				t.Helper()

				cf, err := os.Create(filepath.Join(testDir, "credentials1.yaml"))
				require.NoError(t, err)

				_, err = cf.WriteString(`
  password: rab
`)
				require.NoError(t, err)

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

				wm.EXPECT().Add(cf.Name(), mock.Anything).Return(nil)

				return []byte(fmt.Sprintf("{address: %s, client_cache: {disabled: true}, credentials: { path: %s }}", db.Addr(), cf.Name()))
			},
			assert: func(t *testing.T, err error, cch cache.Cache) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, cch)

				err = cch.Set(context.TODO(), "foo", []byte("bar"), 1*time.Second)
				require.NoError(t, err)

				data, err := cch.Get(context.TODO(), "foo")
				require.NoError(t, err)

				require.Equal(t, []byte("bar"), data)
			},
		},
		{
			uc: "successful cache creation with mutual TLS",
			config: func(t *testing.T, wm *mocks.WatcherMock) []byte {
				t.Helper()

				wm.EXPECT().Add(mock.Anything, mock.Anything).Return(nil)

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

				return []byte(fmt.Sprintf(
					"{address: %s, client_cache: {disabled: true}, tls: {key_store: {path: %s}}}",
					db.Addr(), pemFile.Name(),
				))
			},
			assert: func(t *testing.T, err error, cch cache.Cache) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, cch)

				err = cch.Set(context.TODO(), "foo", []byte("bar"), 1*time.Second)
				require.NoError(t, err)

				data, err := cch.Get(context.TODO(), "foo")
				require.NoError(t, err)

				require.Equal(t, []byte("bar"), data)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			wm := mocks.NewWatcherMock(t)

			conf, err := testsupport.DecodeTestConfig(tc.config(t, wm))
			require.NoError(t, err)

			// WHEN
			cch, err := NewStandaloneCache(conf, wm)
			if err == nil {
				defer cch.Stop(context.TODO())
			}

			// THEN
			tc.assert(t, err, cch)
			wm.AssertExpectations(t)
		})
	}
}
