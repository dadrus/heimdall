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

package joseadapter

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/keystore"
)

func TestToJWK(t *testing.T) {
	t.Parallel()

	rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ecdsaPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	certOnlyPubKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	cert := &x509.Certificate{PublicKey: certOnlyPubKey.Public()}

	for uc, tc := range map[string]struct {
		entry     *keystore.Entry
		assertErr func(t *testing.T, err error)
		assertJWK func(t *testing.T, jwk jose.JSONWebKey)
	}{
		"nil entry": {
			assertErr: func(t *testing.T, err error) {
				t.Helper()
				require.ErrorIs(t, err, ErrNilEntry)
			},
		},
		"unsupported algorithm": {
			entry: &keystore.Entry{Alg: "ED25519", KeySize: 256, PrivateKey: ecdsaPrivKey},
			assertErr: func(t *testing.T, err error) {
				t.Helper()
				require.ErrorIs(t, err, ErrUnsupportedAlg)
			},
		},
		"unsupported rsa size": {
			entry: &keystore.Entry{Alg: keystore.AlgRSA, KeySize: 1024, PrivateKey: rsaPrivKey},
			assertErr: func(t *testing.T, err error) {
				t.Helper()
				require.ErrorIs(t, err, ErrUnsupportedKeySize)
			},
		},
		"missing key material": {
			entry: &keystore.Entry{Alg: keystore.AlgECDSA, KeySize: 256},
			assertErr: func(t *testing.T, err error) {
				t.Helper()
				require.ErrorIs(t, err, ErrNoPublicKeyMaterial)
			},
		},
		"rsa from private key": {
			entry: &keystore.Entry{KeyID: "kid-rsa", Alg: keystore.AlgRSA, KeySize: 2048, PrivateKey: rsaPrivKey},
			assertJWK: func(t *testing.T, jwk jose.JSONWebKey) {
				t.Helper()
				assert.Equal(t, "kid-rsa", jwk.KeyID)
				assert.Equal(t, string(jose.PS256), jwk.Algorithm)
				assert.Equal(t, rsaPrivKey.Public(), jwk.Key)
				assert.Equal(t, "sig", jwk.Use)
			},
		},
		"ecdsa from certificate chain": {
			entry: &keystore.Entry{
				KeyID:     "kid-ecdsa-cert",
				Alg:       keystore.AlgECDSA,
				KeySize:   384,
				CertChain: []*x509.Certificate{cert},
			},
			assertJWK: func(t *testing.T, jwk jose.JSONWebKey) {
				t.Helper()
				assert.Equal(t, "kid-ecdsa-cert", jwk.KeyID)
				assert.Equal(t, string(jose.ES384), jwk.Algorithm)
				assert.Equal(t, cert.PublicKey, jwk.Key)
				assert.Equal(t, "sig", jwk.Use)
				assert.Len(t, jwk.Certificates, 1)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			jwk, err := ToJWK(tc.entry)

			if tc.assertErr != nil {
				require.Error(t, err)
				tc.assertErr(t, err)

				return
			}

			require.NoError(t, err)
			tc.assertJWK(t, jwk)
		})
	}
}
