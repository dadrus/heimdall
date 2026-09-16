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

package authenticators

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/rules/mechanisms/oauth2"
)

func newDPoPJWT(
	t *testing.T,
	key *ecdsa.PrivateKey,
	rawToken string,
	method string,
	uri string,
) string {
	t.Helper()

	tokenHash := sha256.Sum256([]byte(rawToken))
	accessTokenHash := base64.RawURLEncoding.EncodeToString(tokenHash[:])

	options := (&jose.SignerOptions{}).
		WithType("dpop+jwt").
		WithHeader("jwk", jose.JSONWebKey{
			Key:       key.Public(),
			Algorithm: string(jose.ES256),
			Use:       "sig",
		})

	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.ES256,
			Key:       key,
		},
		options,
	)
	require.NoError(t, err)

	proof, err := jwt.Signed(signer).
		Claims(oauth2.DPoPClaims{
			HTTPMethod:      method,
			HTTPURI:         uri,
			AccessTokenHash: accessTokenHash,
			IssuedAt:        oauth2.NumericDate(time.Now().Unix()),
			JTI:             "jti",
		}).
		Serialize()
	require.NoError(t, err)

	return proof
}
