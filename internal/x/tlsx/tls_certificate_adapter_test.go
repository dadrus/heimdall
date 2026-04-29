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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/keystore"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestTLSCertificateFromEntry(t *testing.T) {
	t.Parallel()

	rootCA1, err := testsupport.NewRootCA("Test Root CA 1", time.Hour*24)
	require.NoError(t, err)

	intCA1PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	intCA1Cert, err := rootCA1.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test Int CA 1",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithIsCA(),
		testsupport.WithValidity(time.Now(), time.Hour*24),
		testsupport.WithSubjectPubKey(&intCA1PrivKey.PublicKey, x509.ECDSAWithSHA384))
	require.NoError(t, err)

	intCA1 := testsupport.NewCA(intCA1PrivKey, intCA1Cert)

	ee1PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	ee1Cert, err := intCA1.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test EE 1",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithValidity(time.Now(), time.Hour*24),
		testsupport.WithSubjectPubKey(&ee1PrivKey.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature))
	require.NoError(t, err)

	for uc, tc := range map[string]struct {
		entry  *keystore.Entry
		assert func(t *testing.T, err error, entry *keystore.Entry, tlsCer tls.Certificate)
	}{
		"just the key is present": {
			entry: &keystore.Entry{PrivateKey: ee1PrivKey},
			assert: func(t *testing.T, err error, _ *keystore.Entry, _ tls.Certificate) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, errNoCertificatePresent)
			},
		},
		"only the ee key and cert are present": {
			entry: &keystore.Entry{PrivateKey: ee1PrivKey, CertChain: []*x509.Certificate{ee1Cert}},
			assert: func(t *testing.T, err error, entry *keystore.Entry, tlsCer tls.Certificate) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, tlsCer)

				assert.Equal(t, entry.PrivateKey, tlsCer.PrivateKey)
				assert.Equal(t, entry.CertChain[0], tlsCer.Leaf)
				assert.Len(t, tlsCer.Certificate, 1)
				assert.Equal(t, entry.CertChain[0].Raw, tlsCer.Certificate[0])
			},
		},
		"ee key and cert, as well as all ca certs are present": {
			entry: &keystore.Entry{
				PrivateKey: ee1PrivKey,
				CertChain:  []*x509.Certificate{ee1Cert, intCA1Cert, rootCA1.Certificate},
			},
			assert: func(t *testing.T, err error, entry *keystore.Entry, tlsCer tls.Certificate) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, tlsCer)

				assert.Equal(t, entry.PrivateKey, tlsCer.PrivateKey)
				assert.Equal(t, entry.CertChain[0], tlsCer.Leaf)
				assert.Len(t, tlsCer.Certificate, len(entry.CertChain))

				for i, cert := range entry.CertChain {
					assert.Equal(t, cert.Raw, tlsCer.Certificate[i])
				}
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			cert, err := tlsCertificateFromEntry(tc.entry)
			tc.assert(t, err, tc.entry, cert)
		})
	}
}
