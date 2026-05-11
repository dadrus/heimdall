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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/secrets"
	"github.com/dadrus/heimdall/internal/secrets/types"
)

func TestToJWK(t *testing.T) {
	t.Parallel()

	rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	//nolint:gosec // Intentionally small key size to exercise unsupported RSA-size handling.
	rsaSmallPrivKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	ecdsaPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, ed25519PrivKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	for uc, tc := range map[string]struct {
		secret secrets.AsymmetricKeySecret
		assert func(t *testing.T, err error, jwk jose.JSONWebKey)
	}{
		"nil entry": {
			assert: func(t *testing.T, err error, _ jose.JSONWebKey) {
				t.Helper()

				require.ErrorIs(t, err, ErrNilEntry)
			},
		},
		"unsupported algorithm": {
			secret: types.NewAsymmetricKeySecret("test", "test", "1", unsupportedSigner{key: ed25519PrivKey}, nil),
			assert: func(t *testing.T, err error, _ jose.JSONWebKey) {
				t.Helper()

				require.ErrorIs(t, err, ErrUnsupportedAlgorithm)
			},
		},
		"unsupported rsa size": {
			secret: types.NewAsymmetricKeySecret("test", "test", "1", rsaSmallPrivKey, nil),
			assert: func(t *testing.T, err error, _ jose.JSONWebKey) {
				t.Helper()

				require.ErrorIs(t, err, ErrUnsupportedKeySize)
			},
		},
		"rsa from private key": {
			secret: types.NewAsymmetricKeySecret("test", "test", "kid-rsa", rsaPrivKey, nil),
			assert: func(t *testing.T, err error, jwk jose.JSONWebKey) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "kid-rsa", jwk.KeyID)
				assert.Equal(t, string(jose.PS256), jwk.Algorithm)
				assert.Equal(t, rsaPrivKey.Public(), jwk.Key)
				assert.Equal(t, "sig", jwk.Use)
			},
		},
		"ecdsa from private key": {
			secret: types.NewAsymmetricKeySecret("test", "test", "kid-ecdsa", ecdsaPrivKey, nil),
			assert: func(t *testing.T, err error, jwk jose.JSONWebKey) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "kid-ecdsa", jwk.KeyID)
				assert.Equal(t, string(jose.ES256), jwk.Algorithm)
				assert.Equal(t, ecdsaPrivKey.Public(), jwk.Key)
				assert.Equal(t, "sig", jwk.Use)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			jwk, err := ToJWK(tc.secret)

			tc.assert(t, err, jwk)
		})
	}
}

func TestECDSAAlgorithm(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		curve  elliptic.Curve
		assert func(t *testing.T, alg jose.SignatureAlgorithm, err error)
	}{
		"p256": {
			curve: elliptic.P256(),
			assert: func(t *testing.T, alg jose.SignatureAlgorithm, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, jose.ES256, alg)
			},
		},
		"p384": {
			curve: elliptic.P384(),
			assert: func(t *testing.T, alg jose.SignatureAlgorithm, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, jose.ES384, alg)
			},
		},
		"p521": {
			curve: elliptic.P521(),
			assert: func(t *testing.T, alg jose.SignatureAlgorithm, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, jose.ES512, alg)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			require.NoError(t, err)

			alg, algErr := ecdsaAlgorithm(&key.PublicKey)

			tc.assert(t, alg, algErr)
		})
	}
}

func TestRSAAlgorithm(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		keySize int
		assert  func(t *testing.T, alg jose.SignatureAlgorithm, err error)
	}{
		"2048 bit": {
			keySize: 2048,
			assert: func(t *testing.T, alg jose.SignatureAlgorithm, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, jose.PS256, alg)
			},
		},
		"3072 bit": {
			keySize: 3072,
			assert: func(t *testing.T, alg jose.SignatureAlgorithm, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, jose.PS384, alg)
			},
		},
		"4096 bit": {
			keySize: 4096,
			assert: func(t *testing.T, alg jose.SignatureAlgorithm, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, jose.PS512, alg)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			key, err := rsa.GenerateKey(rand.Reader, tc.keySize)
			require.NoError(t, err)

			alg, algErr := rsaAlgorithm(&key.PublicKey)

			tc.assert(t, alg, algErr)
		})
	}
}

type unsupportedSigner struct {
	key ed25519.PrivateKey
}

func (s unsupportedSigner) Public() crypto.PublicKey {
	return unsupportedPublicKey{}
}

func (s unsupportedSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.key.Sign(rand, digest, opts)
}

type unsupportedPublicKey struct{}
