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

package listener

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
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/pkix/pemx"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func freePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}

	ln, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}

	defer ln.Close()

	return ln.Addr().(*net.TCPAddr).Port, nil // nolint: forcetypeassert
}

func TestNewListener(t *testing.T) {
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
		uc          string
		network     string
		serviceConf config.ServiceConfig
		assert      func(t *testing.T, err error, ln net.Listener, port string)
	}{
		{
			uc:          "creation fails",
			network:     "foo",
			serviceConf: config.ServiceConfig{},
			assert: func(t *testing.T, err error, _ net.Listener, _ string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed creating listener")
			},
		},
		{
			uc:          "without TLS",
			network:     "tcp",
			serviceConf: config.ServiceConfig{Host: "127.0.0.1"},
			assert: func(t *testing.T, err error, ln net.Listener, port string) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, ln)

				assert.Equal(t, "tcp", ln.Addr().Network())
				assert.Equal(t, "127.0.0.1:"+port, ln.Addr().String())
			},
		},
		{
			uc:      "fails due to not existent key store for TLS usage",
			network: "tcp",
			serviceConf: config.ServiceConfig{
				TLS: &config.TLS{KeyStore: config.KeyStore{Path: "/no/such/file"}},
			},
			assert: func(t *testing.T, err error, _ net.Listener, _ string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed loading")
			},
		},
		{
			uc:          "fails due to not specified key store",
			network:     "tcp",
			serviceConf: config.ServiceConfig{TLS: &config.TLS{}},
			assert: func(t *testing.T, err error, _ net.Listener, _ string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no path to tls key store")
			},
		},
		{
			uc:      "successful with specified key id",
			network: "tcp",
			serviceConf: config.ServiceConfig{
				TLS: &config.TLS{
					KeyStore:   config.KeyStore{Path: pemFile.Name()},
					KeyID:      "key1",
					MinVersion: tls.VersionTLS12,
				},
			},
			assert: func(t *testing.T, err error, ln net.Listener, port string) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, ln)
				assert.Equal(t, "tcp", ln.Addr().Network())
				assert.Contains(t, ln.Addr().String(), port)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			port, err := freePort()
			require.NoError(t, err)

			tc.serviceConf.Port = port

			// WHEN
			ln, err := New(tc.network, tc.serviceConf.Address(), tc.serviceConf.TLS, nil)

			// THEN
			defer func() {
				if ln != nil {
					ln.Close()
				}
			}()

			tc.assert(t, err, ln, strconv.Itoa(port))
		})
	}
}
