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
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/x/pkix/pemx"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestKeyStoreCertificate(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc       string
		config   func(t *testing.T, ccm *compatibilityCheckerMock)
		expError bool
	}{
		{
			uc:       "fails",
			expError: true,
			config: func(t *testing.T, ccm *compatibilityCheckerMock) {
				t.Helper()

				ccm.EXPECT().SupportsCertificate(mock.Anything).Return(errors.New("test error"))
			},
		},
		{
			uc: "succeed",
			config: func(t *testing.T, ccm *compatibilityCheckerMock) {
				t.Helper()

				ccm.EXPECT().SupportsCertificate(mock.Anything).Return(nil)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			ks := &keyStore{}

			ccm := newCompatibilityCheckerMock(t)
			tc.config(t, ccm)

			// WHEN
			_, err := ks.certificate(ccm)

			// THEN
			if tc.expError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			ccm.AssertExpectations(t)
		})
	}
}

func TestKeyStoreOnChanged(t *testing.T) {
	t.Parallel()

	// GIVEN
	testDir := t.TempDir()

	privKey1, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	privKey2, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	cert1, err := testsupport.NewCertificateBuilder(testsupport.WithValidity(time.Now(), 10*time.Hour),
		testsupport.WithSerialNumber(big.NewInt(1)),
		testsupport.WithSubject(pkix.Name{
			CommonName:   "test cert 1",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithSubjectPubKey(&privKey1.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithSelfSigned(),
		testsupport.WithSignaturePrivKey(privKey1)).
		Build()
	require.NoError(t, err)

	cert2, err := testsupport.NewCertificateBuilder(testsupport.WithValidity(time.Now(), 10*time.Hour),
		testsupport.WithSerialNumber(big.NewInt(1)),
		testsupport.WithSubject(pkix.Name{
			CommonName:   "test cert 1",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithSubjectPubKey(&privKey2.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithSelfSigned(),
		testsupport.WithSignaturePrivKey(privKey2)).
		Build()
	require.NoError(t, err)

	pemBytes1, err := pemx.BuildPEM(
		pemx.WithECDSAPrivateKey(privKey1, pemx.WithHeader("X-Key-ID", "key1")),
		pemx.WithX509Certificate(cert1),
	)
	require.NoError(t, err)

	pemBytes2, err := pemx.BuildPEM(
		pemx.WithECDSAPrivateKey(privKey2, pemx.WithHeader("X-Key-ID", "key1")),
		pemx.WithX509Certificate(cert2),
	)
	require.NoError(t, err)

	pemFile, err := os.Create(filepath.Join(testDir, "keystore.pem"))
	require.NoError(t, err)

	_, err = pemFile.Write(pemBytes1)
	require.NoError(t, err)

	ks := &keyStore{path: pemFile.Name(), keyID: "key1"}
	ks.load()

	require.Equal(t, cert1, ks.tlsCert.Leaf)

	// WHEN
	_, err = pemFile.Seek(0, 0)
	require.NoError(t, err)

	_, err = pemFile.Write(pemBytes2)
	require.NoError(t, err)

	ks.OnChanged(log.Logger)

	// THEN
	require.Equal(t, cert2, ks.tlsCert.Leaf)

	// WHEN
	err = os.Truncate(pemFile.Name(), 0)
	require.NoError(t, err)

	ks.OnChanged(log.Logger)

	// THEN
	require.Equal(t, cert2, ks.tlsCert.Leaf)
}
