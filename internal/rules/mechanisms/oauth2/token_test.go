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

package oauth2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewToken(t *testing.T) {
	t.Parallel()

	key := newTestKey(t)
	raw := newTestJWT(t, key, Claims{
		Issuer: "issuer",
		Scope:  Scopes{"read", "write"},
	})

	for uc, tc := range map[string]struct {
		tokenType TokenType
		raw       string
		assert    func(t *testing.T, token *Token, err error)
	}{
		"creates token with explicit type": {
			tokenType: TypeDPoP,
			raw:       raw,
			assert: func(t *testing.T, token *Token, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, token)

				assert.Equal(t, raw, token.Raw)
				assert.Equal(t, TypeDPoP, token.Type)
				assert.Equal(t, string(jose.ES256), token.Header.Algorithm)
				assert.NotNil(t, token.RawClaims)
				assert.NotNil(t, token.jwt)
			},
		},
		"returns invalid token error if jwt format is invalid": {
			tokenType: TypeDPoP,
			raw:       "not-a-jwt",
			assert: func(t *testing.T, token *Token, err error) {
				t.Helper()

				require.Nil(t, token)

				var target *InvalidTokenError
				require.ErrorAs(t, err, &target)
				assert.Equal(t, "invalid JWT format", target.message)
				assert.Equal(t, TypeDPoP, target.tokenType)
			},
		},
		"returns invalid token error if jwt payload cannot be deserialized": {
			tokenType: TypeBearer,
			raw:       newTestJWS(t, key, []byte("not-json")),
			assert: func(t *testing.T, token *Token, err error) {
				t.Helper()

				require.Nil(t, token)

				var target *InvalidTokenError
				require.ErrorAs(t, err, &target)
				assert.Equal(t, "failed to deserialize JWT payload", target.message)
				assert.Equal(t, TypeBearer, target.tokenType)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			token, err := NewToken(tc.tokenType, tc.raw)

			tc.assert(t, token, err)
		})
	}
}

func TestNewIntrospectionToken(t *testing.T) {
	t.Parallel()

	claims := Claims{
		Issuer:    "issuer",
		Audience:  Audience{"api"},
		Scope:     Scopes{"read"},
		TokenType: TypeDPoP,
		Confirmation: &Confirmation{
			JWKThumbprint: "thumbprint",
		},
	}

	token := NewIntrospectionToken(TypeDPoP, "opaque-token", claims)

	assert.Equal(t, "opaque-token", token.Raw)
	assert.Equal(t, TypeDPoP, token.Type)
	assert.Equal(t, claims, token.Claims)
	assert.Empty(t, token.Header)
	assert.Nil(t, token.RawClaims)
	assert.Nil(t, token.jwt)
}

func TestTokenVerify(t *testing.T) {
	t.Parallel()

	key := newTestKey(t)
	verificationKey := jose.JSONWebKey{
		Key:       key.Public(),
		Algorithm: string(jose.ES256),
	}

	dateInThePast := NumericDate(time.Now().Add(-time.Minute).Unix())
	dateInTheFuture := NumericDate(time.Now().Add(time.Minute).Unix())

	for uc, tc := range map[string]struct {
		token       func(t *testing.T) *Token
		key         *jose.JSONWebKey
		expectation Expectation
		assert      func(t *testing.T, token *Token, err error)
	}{
		"verifies token and validates claims": {
			token: func(t *testing.T) *Token {
				t.Helper()

				raw := newTestJWT(t, key, Claims{
					Issuer:    "issuer",
					Audience:  Audience{"api"},
					NotBefore: &dateInThePast,
					IssuedAt:  &dateInThePast,
					Scope:     Scopes{"read", "write"},
				})

				token, err := NewToken(TypeBearer, raw)
				require.NoError(t, err)

				return token
			},
			key: &verificationKey,
			expectation: Expectation{
				TrustedIssuers:    []string{"issuer"},
				Audiences:         []string{"api"},
				AllowedAlgorithms: []jose.SignatureAlgorithm{jose.ES256},
				ScopesMatcher:     ExactScopeStrategyMatcher{"read"},
			},
			assert: func(t *testing.T, token *Token, err error) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "issuer", token.Claims.Issuer)
				assert.Equal(t, Audience{"api"}, token.Claims.Audience)
				assert.Equal(t, Scopes{"read", "write"}, token.Claims.Scope)
			},
		},
		"fails if jwt header algorithm does not match key algorithm": {
			token: func(t *testing.T) *Token {
				t.Helper()

				raw := newTestJWT(t, key, Claims{
					Issuer: "issuer",
				})

				token, err := NewToken(TypeBearer, raw)
				require.NoError(t, err)

				return token
			},
			key: &jose.JSONWebKey{
				Key:       key.Public(),
				Algorithm: string(jose.ES384),
			},
			assert: func(t *testing.T, token *Token, err error) {
				t.Helper()

				var target *InvalidTokenError
				require.ErrorAs(t, err, &target)
				assert.Equal(t,
					"algorithm in the JWT header does not match the algorithm referenced in the key",
					target.message,
				)
				assert.Equal(t, TypeBearer, target.tokenType)
				assert.Empty(t, token.Claims)
			},
		},
		"fails if algorithm is not allowed by expectation": {
			token: func(t *testing.T) *Token {
				t.Helper()

				raw := newTestJWT(t, key, Claims{
					Issuer: "issuer",
				})

				token, err := NewToken(TypeBearer, raw)
				require.NoError(t, err)

				return token
			},
			key: &verificationKey,
			expectation: Expectation{
				AllowedAlgorithms: []jose.SignatureAlgorithm{jose.ES384},
			},
			assert: func(t *testing.T, token *Token, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "algorithm")
				assert.Empty(t, token.Claims)
			},
		},
		"fails if signature cannot be verified": {
			token: func(t *testing.T) *Token {
				t.Helper()

				raw := newTestJWT(t, key, Claims{
					Issuer: "issuer",
				})

				token, err := NewToken(TypeDPoP, raw)
				require.NoError(t, err)

				return token
			},
			key: &jose.JSONWebKey{
				Key:       newTestKey(t).Public(),
				Algorithm: string(jose.ES256),
			},
			expectation: Expectation{
				AllowedAlgorithms: []jose.SignatureAlgorithm{jose.ES256},
			},
			assert: func(t *testing.T, token *Token, err error) {
				t.Helper()

				var target *InvalidTokenError
				require.ErrorAs(t, err, &target)
				assert.Equal(t, "failed to verify JWT signature", target.message)
				assert.Equal(t, TypeDPoP, target.tokenType)
				assert.Empty(t, token.Claims)
			},
		},
		"fails if verified claims do not satisfy expectations": {
			token: func(t *testing.T) *Token {
				t.Helper()

				raw := newTestJWT(t, key, Claims{
					Issuer:    "issuer",
					Audience:  Audience{"api"},
					NotBefore: &dateInThePast,
					IssuedAt:  &dateInTheFuture,
				})

				token, err := NewToken(TypeBearer, raw)
				require.NoError(t, err)

				return token
			},
			key: &verificationKey,
			expectation: Expectation{
				TrustedIssuers:    []string{"issuer"},
				Audiences:         []string{"api"},
				AllowedAlgorithms: []jose.SignatureAlgorithm{jose.ES256},
			},
			assert: func(t *testing.T, token *Token, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "issued")

				assert.Equal(t, "issuer", token.Claims.Issuer)
				assert.Equal(t, Audience{"api"}, token.Claims.Audience)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			token := tc.token(t)

			err := token.Verify(nil, tc.expectation, tc.key)

			tc.assert(t, token, err)
		})
	}
}

func TestTokenValidate(t *testing.T) {
	t.Parallel()

	dateInTheFuture := NumericDate(time.Now().Add(1 * time.Minute).Unix())
	dateInThePast := NumericDate(time.Now().Add(-1 * time.Minute).Unix())

	for uc, tc := range map[string]struct {
		token        Token
		expectations Expectation
		assert       func(t *testing.T, err error)
	}{
		"fails on issuer assertion": {
			token: Token{
				Type: TypeBearer,
				Claims: Claims{
					Issuer: "foo",
				},
			},
			expectations: Expectation{
				TrustedIssuers: []string{"bar"},
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "issuer")
			},
		},
		"fails on audience assertion": {
			token: Token{
				Type: TypeBearer,
				Claims: Claims{
					Issuer:   "foo",
					Audience: Audience{"bar"},
				},
			},
			expectations: Expectation{
				TrustedIssuers: []string{"foo"},
				Audiences:      []string{"foo"},
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "audience")
			},
		},
		"fails on validity assertion": {
			token: Token{
				Type: TypeBearer,
				Claims: Claims{
					Issuer:    "foo",
					Audience:  Audience{"bar"},
					NotBefore: &dateInTheFuture,
				},
			},
			expectations: Expectation{
				TrustedIssuers: []string{"foo"},
				Audiences:      []string{"bar"},
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "valid")
			},
		},
		"fails on issuance time assertion": {
			token: Token{
				Type: TypeBearer,
				Claims: Claims{
					Issuer:    "foo",
					Audience:  Audience{"bar"},
					NotBefore: &dateInThePast,
					IssuedAt:  &dateInTheFuture,
				},
			},
			expectations: Expectation{
				TrustedIssuers: []string{"foo"},
				Audiences:      []string{"bar"},
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "issued")
			},
		},
		"fails on scp assertion": {
			token: Token{
				Type: TypeBearer,
				Claims: Claims{
					Issuer:    "foo",
					Audience:  Audience{"bar"},
					NotBefore: &dateInThePast,
					IssuedAt:  &dateInThePast,
					Scp:       Scopes{"foo", "bar"},
				},
			},
			expectations: Expectation{
				TrustedIssuers: []string{"foo"},
				Audiences:      []string{"bar"},
				ScopesMatcher:  ExactScopeStrategyMatcher{"bar", "baz"},
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "scope")
			},
		},
		"fails on scope assertion": {
			token: Token{
				Type: TypeBearer,
				Claims: Claims{
					Issuer:    "foo",
					Audience:  Audience{"bar"},
					NotBefore: &dateInThePast,
					IssuedAt:  &dateInThePast,
					Scope:     Scopes{"foo", "bar"},
				},
			},
			expectations: Expectation{
				TrustedIssuers: []string{"foo"},
				Audiences:      []string{"bar"},
				ScopesMatcher:  ExactScopeStrategyMatcher{"bar", "baz"},
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "scope")
			},
		},
		"succeeds using scope claim": {
			token: Token{
				Type: TypeBearer,
				Claims: Claims{
					Issuer:    "foo",
					Audience:  Audience{"bar"},
					NotBefore: &dateInThePast,
					IssuedAt:  &dateInThePast,
					Scope:     Scopes{"foo", "bar"},
				},
			},
			expectations: Expectation{
				TrustedIssuers: []string{"foo"},
				Audiences:      []string{"bar"},
				ScopesMatcher:  ExactScopeStrategyMatcher{"foo"},
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"succeeds using scp claim": {
			token: Token{
				Type: TypeBearer,
				Claims: Claims{
					Issuer:    "foo",
					Audience:  Audience{"bar"},
					NotBefore: &dateInThePast,
					IssuedAt:  &dateInThePast,
					Scp:       Scopes{"foo", "bar"},
				},
			},
			expectations: Expectation{
				TrustedIssuers: []string{"foo"},
				Audiences:      []string{"bar"},
				ScopesMatcher:  ExactScopeStrategyMatcher{"foo"},
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"fails on proof of possession due to invalid token scheme": {
			token: Token{
				Type: TypeBearer,
				Claims: Claims{
					Issuer:    "foo",
					Audience:  Audience{"bar"},
					NotBefore: &dateInThePast,
					IssuedAt:  &dateInThePast,
					Confirmation: &Confirmation{
						JWKThumbprint: "foo",
					},
				},
			},
			expectations: Expectation{
				TrustedIssuers: []string{"foo"},
				ScopesMatcher:  NoopMatcher{},
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "DPoP expected")
			},
		},
		"fails on proof of possession due to missing cnf claim": {
			token: Token{
				Type: TypeDPoP,
				Claims: Claims{
					Issuer:    "foo",
					Audience:  Audience{"bar"},
					NotBefore: &dateInThePast,
					IssuedAt:  &dateInThePast,
				},
			},
			expectations: Expectation{
				TrustedIssuers:    []string{"foo"},
				ScopesMatcher:     NoopMatcher{},
				ProofOfPossession: &DPoPStrategy{},
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "proof of possession is required")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			err := tc.token.Validate(nil, tc.expectations)

			tc.assert(t, err)
		})
	}
}

func newTestJWT(t *testing.T, key *ecdsa.PrivateKey, claims Claims) string {
	t.Helper()

	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.ES256,
			Key:       key,
		},
		nil,
	)
	require.NoError(t, err)

	raw, err := jwt.Signed(signer).
		Claims(claims).
		Serialize()
	require.NoError(t, err)

	return raw
}

func newTestJWS(t *testing.T, key *ecdsa.PrivateKey, payload []byte) string {
	t.Helper()

	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.ES256,
			Key:       key,
		},
		nil,
	)
	require.NoError(t, err)

	jws, err := signer.Sign(payload)
	require.NoError(t, err)

	raw, err := jws.CompactSerialize()
	require.NoError(t, err)

	return raw
}

func newTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	return key
}
