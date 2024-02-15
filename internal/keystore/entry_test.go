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

package keystore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestEntryToJWK(t *testing.T) {
	t.Parallel()

	rsaPrivKey1, err := rsa.GenerateKey(rand.Reader, rsa2048)
	require.NoError(t, err)

	rsaPrivKey2, err := rsa.GenerateKey(rand.Reader, rsa3072)
	require.NoError(t, err)

	rsaPrivKey3, err := rsa.GenerateKey(rand.Reader, rsa4096)
	require.NoError(t, err)

	ecdsaPrivKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ecdsaPrivKey2, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	ecdsaPrivKey3, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	for _, tc := range []struct {
		uc     string
		entry  *Entry
		assert func(t *testing.T, entry *Entry, jwk jose.JSONWebKey)
	}{
		{
			uc:    "rsa 2048 key",
			entry: &Entry{KeyID: "foo", Alg: AlgRSA, PrivateKey: rsaPrivKey1, KeySize: rsa2048},
			assert: func(t *testing.T, entry *Entry, jwk jose.JSONWebKey) {
				t.Helper()

				assert.Equal(t, entry.KeyID, jwk.KeyID)
				assert.Equal(t, entry.PrivateKey.Public(), jwk.Key)
				assert.Equal(t, "sig", jwk.Use)
				assert.Equal(t, string(jose.PS256), jwk.Algorithm)
				assert.Empty(t, jwk.Certificates)
				assert.Nil(t, jwk.CertificatesURL)
				assert.Empty(t, jwk.CertificateThumbprintSHA1)
				assert.Empty(t, jwk.CertificateThumbprintSHA256)
			},
		},
		{
			uc:    "rsa 3072 key",
			entry: &Entry{KeyID: "bar", Alg: AlgRSA, PrivateKey: rsaPrivKey2, KeySize: rsa3072},
			assert: func(t *testing.T, entry *Entry, jwk jose.JSONWebKey) {
				t.Helper()

				assert.Equal(t, entry.KeyID, jwk.KeyID)
				assert.Equal(t, entry.PrivateKey.Public(), jwk.Key)
				assert.Equal(t, "sig", jwk.Use)
				assert.Equal(t, string(jose.PS384), jwk.Algorithm)
				assert.Empty(t, jwk.Certificates)
				assert.Nil(t, jwk.CertificatesURL)
				assert.Empty(t, jwk.CertificateThumbprintSHA1)
				assert.Empty(t, jwk.CertificateThumbprintSHA256)
			},
		},
		{
			uc:    "rsa 4096 key",
			entry: &Entry{KeyID: "baz", Alg: AlgRSA, PrivateKey: rsaPrivKey3, KeySize: rsa4096},
			assert: func(t *testing.T, entry *Entry, jwk jose.JSONWebKey) {
				t.Helper()

				assert.Equal(t, entry.KeyID, jwk.KeyID)
				assert.Equal(t, entry.PrivateKey.Public(), jwk.Key)
				assert.Equal(t, "sig", jwk.Use)
				assert.Equal(t, string(jose.PS512), jwk.Algorithm)
				assert.Empty(t, jwk.Certificates)
				assert.Nil(t, jwk.CertificatesURL)
				assert.Empty(t, jwk.CertificateThumbprintSHA1)
				assert.Empty(t, jwk.CertificateThumbprintSHA256)
			},
		},
		{
			uc:    "ec P256 key",
			entry: &Entry{KeyID: "foo", Alg: AlgECDSA, PrivateKey: ecdsaPrivKey1, KeySize: ecdsa256},
			assert: func(t *testing.T, entry *Entry, jwk jose.JSONWebKey) {
				t.Helper()

				assert.Equal(t, entry.KeyID, jwk.KeyID)
				assert.Equal(t, entry.PrivateKey.Public(), jwk.Key)
				assert.Equal(t, "sig", jwk.Use)
				assert.Equal(t, string(jose.ES256), jwk.Algorithm)
				assert.Empty(t, jwk.Certificates)
				assert.Nil(t, jwk.CertificatesURL)
				assert.Empty(t, jwk.CertificateThumbprintSHA1)
				assert.Empty(t, jwk.CertificateThumbprintSHA256)
			},
		},
		{
			uc:    "ec P384 key",
			entry: &Entry{KeyID: "bar", Alg: AlgECDSA, PrivateKey: ecdsaPrivKey2, KeySize: ecdsa384},
			assert: func(t *testing.T, entry *Entry, jwk jose.JSONWebKey) {
				t.Helper()

				assert.Equal(t, entry.KeyID, jwk.KeyID)
				assert.Equal(t, entry.PrivateKey.Public(), jwk.Key)
				assert.Equal(t, "sig", jwk.Use)
				assert.Equal(t, string(jose.ES384), jwk.Algorithm)
				assert.Empty(t, jwk.Certificates)
				assert.Nil(t, jwk.CertificatesURL)
				assert.Empty(t, jwk.CertificateThumbprintSHA1)
				assert.Empty(t, jwk.CertificateThumbprintSHA256)
			},
		},
		{
			uc:    "ec P512 key",
			entry: &Entry{KeyID: "zab", Alg: AlgECDSA, PrivateKey: ecdsaPrivKey3, KeySize: ecdsa512},
			assert: func(t *testing.T, entry *Entry, jwk jose.JSONWebKey) {
				t.Helper()

				assert.Equal(t, entry.KeyID, jwk.KeyID)
				assert.Equal(t, entry.PrivateKey.Public(), jwk.Key)
				assert.Equal(t, "sig", jwk.Use)
				assert.Equal(t, string(jose.ES512), jwk.Algorithm)
				assert.Empty(t, jwk.Certificates)
				assert.Nil(t, jwk.CertificatesURL)
				assert.Empty(t, jwk.CertificateThumbprintSHA1)
				assert.Empty(t, jwk.CertificateThumbprintSHA256)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			// WHEN
			jwk := tc.entry.JWK()

			// THEN
			tc.assert(t, tc.entry, jwk)
		})
	}
}

func TestEntryToTLSCertificate(t *testing.T) {
	t.Parallel()

	// ROOT CAs
	rootCA1, err := testsupport.NewRootCA("Test Root CA 1", time.Hour*24)
	require.NoError(t, err)

	// INT CA
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

	// EE CERTS
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

	for _, tc := range []struct {
		uc     string
		entry  *Entry
		assert func(t *testing.T, err error, entry *Entry, tlsCer tls.Certificate)
	}{
		{
			uc:    "just the key is present",
			entry: &Entry{PrivateKey: ee1PrivKey},
			assert: func(t *testing.T, err error, _ *Entry, _ tls.Certificate) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrNoCertificatePresent)
			},
		},
		{
			uc:    "only the ee key and cert are present",
			entry: &Entry{PrivateKey: ee1PrivKey, CertChain: []*x509.Certificate{ee1Cert}},
			assert: func(t *testing.T, err error, entry *Entry, tlsCer tls.Certificate) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, tlsCer)

				assert.Equal(t, entry.PrivateKey, tlsCer.PrivateKey)
				assert.Equal(t, entry.CertChain[0], tlsCer.Leaf)
				assert.Len(t, tlsCer.Certificate, 1)
				assert.Equal(t, entry.CertChain[0].Raw, tlsCer.Certificate[0])
			},
		},
		{
			uc: "ee key and cert, as well as all ca certs are present",
			entry: &Entry{
				PrivateKey: ee1PrivKey,
				CertChain:  []*x509.Certificate{ee1Cert, intCA1Cert, rootCA1.Certificate},
			},
			assert: func(t *testing.T, err error, entry *Entry, tlsCer tls.Certificate) {
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
		t.Run(tc.uc, func(t *testing.T) {
			// WHEN
			cert, err := tc.entry.TLSCertificate()

			// THEN
			tc.assert(t, err, tc.entry, cert)
		})
	}
}
