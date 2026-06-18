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

package oauth2

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/cache"
	cacheMocks "github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/pipeline"
	pipelineMocks "github.com/dadrus/heimdall/internal/pipeline/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/nonce"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

func TestDPoPClaimsValidate(t *testing.T) {
	t.Parallel()

	const rawToken = "access-token"

	now := time.Now().UTC()
	maxAge := time.Minute
	leeway := 10 * time.Second

	tokenHash := sha256.Sum256(stringx.ToBytes(rawToken))
	accessTokenHash := base64.RawURLEncoding.EncodeToString(tokenHash[:])

	jtiHash := sha256.Sum256(stringx.ToBytes("jti"))
	jtiCacheKey := "dpop:jti:" + base64.RawURLEncoding.EncodeToString(jtiHash[:])

	parsedURL, err := url.Parse("https://api.example.com/resource?foo=bar#fragment")
	require.NoError(t, err)

	request := &pipeline.Request{
		Method: http.MethodGet,
		URL: &pipeline.URL{
			URL: *parsedURL,
		},
	}

	validClaims := DPoPClaims{
		HTTPMethod:      http.MethodGet,
		HTTPURI:         "https://api.example.com/resource",
		AccessTokenHash: accessTokenHash,
		IssuedAt:        NumericDate(now.Add(-10 * time.Second).Unix()),
		JTI:             "jti",
	}

	nonceKey := nonce.Key{
		KID:   "key-1",
		Value: stringx.ToBytes("0123456789abcdef0123456789abcdef"),
	}

	validNonce, err := nonce.NewNonce(
		nonceKey,
		nonce.WithBinding(tokenHash),
	)
	require.NoError(t, err)

	wrongBindingNonce, err := nonce.NewNonce(
		nonceKey,
		nonce.WithBinding(sha256.Sum256(stringx.ToBytes("other-token"))),
	)
	require.NoError(t, err)

	for uc, tc := range map[string]struct {
		claims        DPoPClaims
		replayAllowed bool
		nonceRequired bool
		setup         func(t *testing.T, cch *cacheMocks.CacheMock, nh *NonceHandlerMock)
		assert        func(t *testing.T, err error)
	}{
		"valid proof without nonce": {
			claims: validClaims,
			setup: func(t *testing.T, cch *cacheMocks.CacheMock, _ *NonceHandlerMock) {
				t.Helper()

				cch.EXPECT().
					Get(mock.Anything, jtiCacheKey).
					Return(nil, cache.ErrNoEntry)

				cch.EXPECT().
					Set(mock.Anything, jtiCacheKey, []byte{1}, mock.AnythingOfType("time.Duration")).
					Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"valid proof with replay allowed does not access cache": {
			claims:        validClaims,
			replayAllowed: true,
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"valid proof with nonce": {
			claims: func() DPoPClaims {
				claims := validClaims
				claims.Nonce = validNonce

				return claims
			}(),
			nonceRequired: true,
			setup: func(t *testing.T, cch *cacheMocks.CacheMock, nh *NonceHandlerMock) {
				t.Helper()

				cch.EXPECT().
					Get(mock.Anything, jtiCacheKey).
					Return(nil, cache.ErrNoEntry)

				nh.EXPECT().
					ResolveKey(nonceKey.KID).
					Return(nonceKey, nil)

				cch.EXPECT().
					Set(mock.Anything, jtiCacheKey, []byte{1}, mock.Anything).
					Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"fails if jti is missing": {
			claims: func() DPoPClaims {
				claims := validClaims
				claims.JTI = ""

				return claims
			}(),
			assert: func(t *testing.T, err error) {
				t.Helper()

				var target *InvalidDPoPProofError
				require.ErrorAs(t, err, &target)
				require.ErrorContains(t, err, "jti is missing")

				assert.Equal(t, "jti is missing", target.message)
				assert.Equal(t, TypeDPoP, target.tokenType)
			},
		},
		"fails if proof is replayed": {
			claims: validClaims,
			setup: func(t *testing.T, cch *cacheMocks.CacheMock, _ *NonceHandlerMock) {
				t.Helper()

				cch.EXPECT().
					Get(mock.Anything, jtiCacheKey).
					Return([]byte{1}, nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				var target *InvalidDPoPProofError
				require.ErrorAs(t, err, &target)
				require.ErrorContains(t, err, "replay detected")

				assert.Equal(t, "replay detected", target.message)
				assert.Equal(t, TypeDPoP, target.tokenType)
			},
		},
		"fails if iat is missing": {
			claims: func() DPoPClaims {
				claims := validClaims
				claims.IssuedAt = NumericDate(0)

				return claims
			}(),
			setup: func(t *testing.T, cch *cacheMocks.CacheMock, _ *NonceHandlerMock) {
				t.Helper()

				cch.EXPECT().
					Get(mock.Anything, jtiCacheKey).
					Return(nil, cache.ErrNoEntry)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				var target *InvalidDPoPProofError
				require.ErrorAs(t, err, &target)
				require.ErrorContains(t, err, "proof is too old")

				assert.Equal(t, "proof is too old", target.message)
				assert.Equal(t, TypeDPoP, target.tokenType)
			},
		},
		"fails if iat is in the future beyond leeway": {
			claims: func() DPoPClaims {
				claims := validClaims
				claims.IssuedAt = NumericDate(now.Add(leeway + time.Second).Unix())

				return claims
			}(),
			setup: func(t *testing.T, cch *cacheMocks.CacheMock, _ *NonceHandlerMock) {
				t.Helper()

				cch.EXPECT().
					Get(mock.Anything, jtiCacheKey).
					Return(nil, cache.ErrNoEntry)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				var target *InvalidDPoPProofError
				require.ErrorAs(t, err, &target)
				require.ErrorContains(t, err, "iat is in the future")

				assert.Equal(t, "iat is in the future", target.message)
				assert.Equal(t, TypeDPoP, target.tokenType)
			},
		},
		"accepts iat in the future within leeway": {
			claims: func() DPoPClaims {
				claims := validClaims
				claims.IssuedAt = NumericDate(now.Add(leeway / 2).Unix())

				return claims
			}(),
			setup: func(t *testing.T, cch *cacheMocks.CacheMock, _ *NonceHandlerMock) {
				t.Helper()

				cch.EXPECT().
					Get(mock.Anything, jtiCacheKey).
					Return(nil, cache.ErrNoEntry)

				cch.EXPECT().
					Set(mock.Anything, jtiCacheKey, []byte{1}, mock.AnythingOfType("time.Duration")).
					Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"fails if proof is too old": {
			claims: func() DPoPClaims {
				claims := validClaims
				claims.IssuedAt = NumericDate(now.Add(-(maxAge + leeway + time.Second)).Unix())

				return claims
			}(),
			setup: func(t *testing.T, cch *cacheMocks.CacheMock, _ *NonceHandlerMock) {
				t.Helper()

				cch.EXPECT().
					Get(mock.Anything, jtiCacheKey).
					Return(nil, cache.ErrNoEntry)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				var target *InvalidDPoPProofError
				require.ErrorAs(t, err, &target)
				require.ErrorContains(t, err, "proof is too old")

				assert.Equal(t, "proof is too old", target.message)
				assert.Equal(t, TypeDPoP, target.tokenType)
			},
		},
		"fails if htm does not match request method": {
			claims: func() DPoPClaims {
				claims := validClaims
				claims.HTTPMethod = http.MethodPost

				return claims
			}(),
			setup: func(t *testing.T, cch *cacheMocks.CacheMock, _ *NonceHandlerMock) {
				t.Helper()

				cch.EXPECT().
					Get(mock.Anything, jtiCacheKey).
					Return(nil, cache.ErrNoEntry)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				var target *InvalidDPoPProofError
				require.ErrorAs(t, err, &target)
				require.ErrorContains(t, err, "htm does not match request method")

				assert.Equal(t, "htm does not match request method", target.message)
				assert.Equal(t, TypeDPoP, target.tokenType)
			},
		},
		"fails if htu does not match request uri": {
			claims: func() DPoPClaims {
				claims := validClaims
				claims.HTTPURI = "https://api.example.com/other"

				return claims
			}(),
			setup: func(t *testing.T, cch *cacheMocks.CacheMock, _ *NonceHandlerMock) {
				t.Helper()

				cch.EXPECT().
					Get(mock.Anything, jtiCacheKey).
					Return(nil, cache.ErrNoEntry)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				var target *InvalidDPoPProofError
				require.ErrorAs(t, err, &target)
				require.ErrorContains(t, err, "htu does not match request URI")

				assert.Equal(t, "htu does not match request URI", target.message)
				assert.Equal(t, TypeDPoP, target.tokenType)
			},
		},
		"fails if htu contains query": {
			claims: func() DPoPClaims {
				claims := validClaims
				claims.HTTPURI = "https://api.example.com/resource?foo=bar"

				return claims
			}(),
			setup: func(t *testing.T, cch *cacheMocks.CacheMock, _ *NonceHandlerMock) {
				t.Helper()

				cch.EXPECT().
					Get(mock.Anything, jtiCacheKey).
					Return(nil, cache.ErrNoEntry)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				var target *InvalidDPoPProofError
				require.ErrorAs(t, err, &target)
				require.ErrorContains(t, err, "htu does not match request URI")

				assert.Equal(t, "htu does not match request URI", target.message)
				assert.Equal(t, TypeDPoP, target.tokenType)
			},
		},
		"fails if ath is malformed": {
			claims: func() DPoPClaims {
				claims := validClaims
				claims.AccessTokenHash = "%"

				return claims
			}(),
			setup: func(t *testing.T, cch *cacheMocks.CacheMock, _ *NonceHandlerMock) {
				t.Helper()

				cch.EXPECT().
					Get(mock.Anything, jtiCacheKey).
					Return(nil, cache.ErrNoEntry)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				var target *InvalidDPoPProofError
				require.ErrorAs(t, err, &target)
				require.ErrorContains(t, err, "ath is malformed")

				assert.Equal(t, "ath is malformed", target.message)
				assert.Equal(t, TypeDPoP, target.tokenType)
			},
		},
		"fails if ath does not match token hash": {
			claims: func() DPoPClaims {
				claims := validClaims
				otherHash := sha256.Sum256(stringx.ToBytes("other-token"))
				claims.AccessTokenHash = base64.RawURLEncoding.EncodeToString(otherHash[:])

				return claims
			}(),
			setup: func(t *testing.T, cch *cacheMocks.CacheMock, _ *NonceHandlerMock) {
				t.Helper()

				cch.EXPECT().
					Get(mock.Anything, jtiCacheKey).
					Return(nil, cache.ErrNoEntry)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				var target *InvalidDPoPProofError
				require.ErrorAs(t, err, &target)
				require.ErrorContains(t, err, "ath does not match expected token hash value")

				assert.Equal(t, "ath does not match expected token hash value", target.message)
				assert.Equal(t, TypeDPoP, target.tokenType)
			},
		},
		"fails if nonce is required but missing": {
			claims:        validClaims,
			nonceRequired: true,
			setup: func(t *testing.T, cch *cacheMocks.CacheMock, _ *NonceHandlerMock) {
				t.Helper()

				cch.EXPECT().
					Get(mock.Anything, jtiCacheKey).
					Return(nil, cache.ErrNoEntry)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				var target *UseDPoPNonceError
				require.ErrorAs(t, err, &target)
				require.ErrorContains(t, err, "nonce is missing")

				assert.Equal(t, "nonce is missing", target.message)
				assert.Equal(t, TypeDPoP, target.tokenType)
				assert.Equal(t, tokenHash, target.binding)
				assert.NotNil(t, target.issuer)
			},
		},
		"fails if nonce is invalid": {
			claims: func() DPoPClaims {
				claims := validClaims
				claims.Nonce = "invalid"

				return claims
			}(),
			nonceRequired: true,
			setup: func(t *testing.T, cch *cacheMocks.CacheMock, _ *NonceHandlerMock) {
				t.Helper()

				cch.EXPECT().
					Get(mock.Anything, jtiCacheKey).
					Return(nil, cache.ErrNoEntry)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				var target *UseDPoPNonceError
				require.ErrorAs(t, err, &target)
				require.ErrorContains(t, err, "nonce is invalid")

				assert.Equal(t, "nonce is invalid", target.message)
				assert.Equal(t, TypeDPoP, target.tokenType)
				assert.Equal(t, tokenHash, target.binding)
				assert.NotNil(t, target.issuer)
			},
		},
		"fails if nonce binding does not match": {
			claims: func() DPoPClaims {
				claims := validClaims
				claims.Nonce = wrongBindingNonce

				return claims
			}(),
			nonceRequired: true,
			setup: func(t *testing.T, cch *cacheMocks.CacheMock, nh *NonceHandlerMock) {
				t.Helper()

				cch.EXPECT().
					Get(mock.Anything, jtiCacheKey).
					Return(nil, cache.ErrNoEntry)

				nh.EXPECT().
					ResolveKey(nonceKey.KID).
					Return(nonceKey, nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				var target *UseDPoPNonceError
				require.ErrorAs(t, err, &target)
				require.ErrorContains(t, err, "nonce is invalid")

				assert.Equal(t, "nonce is invalid", target.message)
				assert.Equal(t, TypeDPoP, target.tokenType)
				assert.Equal(t, tokenHash, target.binding)
				assert.NotNil(t, target.issuer)
			},
		},
		"fails if nonce key cannot be resolved": {
			claims: func() DPoPClaims {
				claims := validClaims
				claims.Nonce = validNonce

				return claims
			}(),
			nonceRequired: true,
			setup: func(t *testing.T, cch *cacheMocks.CacheMock, nh *NonceHandlerMock) {
				t.Helper()

				cch.EXPECT().
					Get(mock.Anything, jtiCacheKey).
					Return(nil, cache.ErrNoEntry)

				nh.EXPECT().
					ResolveKey(nonceKey.KID).
					Return(nonce.Key{}, assert.AnError)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				var target *UseDPoPNonceError
				require.ErrorAs(t, err, &target)
				require.ErrorContains(t, err, "nonce is invalid")

				assert.Equal(t, "nonce is invalid", target.message)
				assert.Equal(t, TypeDPoP, target.tokenType)
				assert.Equal(t, tokenHash, target.binding)
				assert.NotNil(t, target.issuer)
			},
		},
		"fails if jti cannot be remembered": {
			claims: validClaims,
			setup: func(t *testing.T, cch *cacheMocks.CacheMock, _ *NonceHandlerMock) {
				t.Helper()

				cch.EXPECT().
					Get(mock.Anything, jtiCacheKey).
					Return(nil, cache.ErrNoEntry)

				cch.EXPECT().
					Set(mock.Anything, jtiCacheKey, []byte{1}, mock.AnythingOfType("time.Duration")).
					Return(errors.New("cache failure"))
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.ErrorIs(t, err, pipeline.ErrInternal)
				require.ErrorContains(t, err, "failed to remember DPoP proof jti")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			nh := NewNonceHandlerMock(t)
			cch := cacheMocks.NewCacheMock(t)

			if tc.setup != nil {
				tc.setup(t, cch, nh)
			}

			ctx := cache.WithContext(context.Background(), cch)

			pctx := pipelineMocks.NewContextMock(t)
			pctx.EXPECT().Request().Return(request).Maybe()
			pctx.EXPECT().Context().Return(ctx).Maybe()

			err := tc.claims.Validate(
				pctx,
				nh,
				maxAge,
				leeway,
				tc.replayAllowed,
				tc.nonceRequired,
				rawToken,
			)

			tc.assert(t, err)
		})
	}
}
