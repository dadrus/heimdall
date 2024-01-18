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
	"testing"

	"github.com/go-jose/go-jose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
