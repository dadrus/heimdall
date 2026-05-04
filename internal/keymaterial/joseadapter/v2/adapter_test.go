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

	ecdsaPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	for uc, tc := range map[string]struct {
		secret    secrets.AsymmetricKeySecret
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
			secret: types.NewAsymmetricKeySecret("test", "test", "1", ecdsaPrivKey, nil),
			assertErr: func(t *testing.T, err error) {
				t.Helper()
				require.ErrorIs(t, err, ErrUnsupportedAlg)
			},
		},
		"unsupported rsa size": {
			secret: types.NewAsymmetricKeySecret("test", "test", "1", rsaPrivKey, nil),
			assertErr: func(t *testing.T, err error) {
				t.Helper()
				require.ErrorIs(t, err, ErrUnsupportedKeySize)
			},
		},
		"rsa from private key": {
			secret: types.NewAsymmetricKeySecret("test", "test", "kid-rsa", rsaPrivKey, nil),
			assertJWK: func(t *testing.T, jwk jose.JSONWebKey) {
				t.Helper()
				assert.Equal(t, "kid-rsa", jwk.KeyID)
				assert.Equal(t, string(jose.PS256), jwk.Algorithm)
				assert.Equal(t, rsaPrivKey.Public(), jwk.Key)
				assert.Equal(t, "sig", jwk.Use)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			jwk, err := ToJWK(tc.secret)

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
