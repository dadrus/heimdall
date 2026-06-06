// Copyright 2026 Dimitrij Drus
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package pkix

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	x509pkix "crypto/x509/pkix"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/secrets/provider"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestFindChain(t *testing.T) {
	t.Parallel()

	rootCA, intermediateCA, leafCert, privateKey := createLeafWithIntermediateCA(t)

	for uc, tc := range map[string]struct {
		pool   []*x509.Certificate
		key    crypto.PublicKey
		assert func(*testing.T, []*x509.Certificate)
	}{
		"returns full chain": {
			pool: []*x509.Certificate{
				leafCert,
				intermediateCA.Certificate,
				rootCA.Certificate,
			},
			key: privateKey.Public(),
			assert: func(t *testing.T, chain []*x509.Certificate) {
				t.Helper()

				require.Len(t, chain, 3)
				assert.True(t, chain[0].Equal(leafCert))
				assert.True(t, chain[1].Equal(intermediateCA.Certificate))
				assert.True(t, chain[2].Equal(rootCA.Certificate))
			},
		},
		"returns only the leaf certificate if intermediate is missing": {
			pool: []*x509.Certificate{
				leafCert,
				rootCA.Certificate,
			},
			key: privateKey.Public(),
			assert: func(t *testing.T, chain []*x509.Certificate) {
				t.Helper()

				require.Len(t, chain, 1)
				assert.True(t, chain[0].Equal(leafCert))
			},
		},
		"returns nil if no matching certificate exists": {
			pool: []*x509.Certificate{
				rootCA.Certificate,
				intermediateCA.Certificate,
			},
			key: privateKey.Public(),
			assert: func(t *testing.T, chain []*x509.Certificate) {
				t.Helper()

				assert.Nil(t, chain)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, FindChain(tc.key, tc.pool))
		})
	}
}

func TestValidateChain(t *testing.T) {
	t.Parallel()

	rootCA, intermediateCA, leafCert, _ := createLeafWithIntermediateCA(t)
	badRootCA, err := testsupport.NewRootCA("PEM Bad Root CA", 24*time.Hour)
	require.NoError(t, err)

	for uc, tc := range map[string]struct {
		chain  []*x509.Certificate
		assert func(*testing.T, error)
	}{
		"accepts valid chain": {
			chain: []*x509.Certificate{
				leafCert,
				intermediateCA.Certificate,
				rootCA.Certificate,
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"accepts single certificate as explicitly trusted": {
			chain: []*x509.Certificate{
				leafCert,
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"returns configuration error for incomplete chain": {
			chain: []*x509.Certificate{
				leafCert,
				rootCA.Certificate,
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "invalid certificate chain")
			},
		},
		"returns configuration error for malformed issuer": {
			chain: []*x509.Certificate{
				leafCert,
				intermediateCA.Certificate,
				badRootCA.Certificate,
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "invalid certificate chain")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, ValidateChain(tc.chain))
		})
	}
}

func createLeafWithIntermediateCA(
	t *testing.T,
) (*testsupport.CA, *testsupport.CA, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	rootCA, err := testsupport.NewRootCA("PEM Test Root CA", 24*time.Hour)
	require.NoError(t, err)

	intermediateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	intermediateCert, err := rootCA.IssueCertificate(
		testsupport.WithSubject(x509pkix.Name{
			CommonName:   "PEM Test Intermediate CA",
			Organization: []string{"Heimdall"},
			Country:      []string{"EU"},
		}),
		testsupport.WithValidity(time.Now(), time.Hour),
		testsupport.WithSubjectPubKey(&intermediateKey.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithIsCA(),
		testsupport.WithGeneratedSubjectKeyID(),
	)
	require.NoError(t, err)

	intermediateCA := testsupport.NewCA(intermediateKey, intermediateCert)

	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	leafCert, err := intermediateCA.IssueCertificate(
		testsupport.WithSubject(x509pkix.Name{
			CommonName:   "PEM Test EE",
			Organization: []string{"Heimdall"},
			Country:      []string{"EU"},
		}),
		testsupport.WithValidity(time.Now(), time.Hour),
		testsupport.WithSubjectPubKey(&privateKey.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature),
		testsupport.WithGeneratedSubjectKeyID(),
	)
	require.NoError(t, err)

	return rootCA, intermediateCA, leafCert, privateKey
}
