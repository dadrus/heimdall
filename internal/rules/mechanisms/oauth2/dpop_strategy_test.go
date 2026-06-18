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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/cache"
	cacheMocks "github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/pipeline"
	pipelineMocks "github.com/dadrus/heimdall/internal/pipeline/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/nonce"
	"github.com/dadrus/heimdall/internal/secrets"
	secretsmocks "github.com/dadrus/heimdall/internal/secrets/mocks"
	secrettypes "github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

func TestNonceManagerResolveKey(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		manager nonceManager
		kid     string
		assert  func(t *testing.T, key nonce.Key, err error)
	}{
		"resolves known key": {
			manager: nonceManager{
				keys: []nonce.Key{
					{KID: "key-1", Value: []byte("key-1-value")},
					{KID: "key-2", Value: []byte("key-2-value")},
				},
			},
			kid: "key-2",
			assert: func(t *testing.T, key nonce.Key, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "key-2", key.KID)
				assert.Equal(t, []byte("key-2-value"), key.Value)
			},
		},
		"returns error for unknown key": {
			manager: nonceManager{
				keys: []nonce.Key{
					{KID: "key-1", Value: []byte("key-1-value")},
				},
			},
			kid: "unknown",
			assert: func(t *testing.T, key nonce.Key, err error) {
				t.Helper()

				require.ErrorIs(t, err, errKeyUnknown)
				require.ErrorContains(t, err, "key id referenced in nonce does not match any known master key")
				assert.Empty(t, key.KID)
				assert.Nil(t, key.Value)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			key, err := tc.manager.ResolveKey(tc.kid)

			tc.assert(t, key, err)
		})
	}
}

func TestNonceManagerIssueNonce(t *testing.T) {
	t.Parallel()

	binding := sha256.Sum256(stringx.ToBytes("access-token"))
	manager := nonceManager{
		current: nonce.Key{
			KID:   "key-1",
			Value: stringx.ToBytes("0123456789abcdef0123456789abcdef"),
		},
		keys: []nonce.Key{
			{
				KID:   "key-1",
				Value: stringx.ToBytes("0123456789abcdef0123456789abcdef"),
			},
		},
	}

	value, err := manager.IssueNonce(binding)

	require.NoError(t, err)
	require.NotEmpty(t, value)
	require.NoError(t, nonce.ValidateNonce(
		value,
		manager,
		nonce.WithBinding(binding),
		nonce.WithMaxAge(time.Minute),
	))
}

func TestNewDPoPStrategy(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		conf  map[string]any
		setup func(
			t *testing.T,
			appCtx *app.ContextMock,
			resolver *secretsmocks.ResolverMock,
		)
		assert func(t *testing.T, strategy PoPStrategy, err error)
	}{
		"creates strategy without configuration": {
			conf: map[string]any{},
			assert: func(t *testing.T, strategy PoPStrategy, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, strategy)

				typed, ok := strategy.(*DPoPStrategy)
				require.True(t, ok)

				assert.Equal(t, 1*time.Minute, typed.MaxAge)
				assert.Nil(t, typed.RequireNonce)
				assert.Nil(t, typed.ReplayAllowed)
				assert.Nil(t, typed.setInformer)
				assert.Empty(t, typed.currentKID)
			},
		},
		"creates strategy with explicit configuration": {
			conf: map[string]any{
				"max_age":        "1m",
				"nonce_required": false,
				"replay_allowed": true,
			},
			assert: func(t *testing.T, strategy PoPStrategy, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, strategy)

				typed, ok := strategy.(*DPoPStrategy)
				require.True(t, ok)

				assert.Equal(t, time.Minute, typed.MaxAge)

				require.NotNil(t, typed.RequireNonce)
				assert.False(t, *typed.RequireNonce)

				require.NotNil(t, typed.ReplayAllowed)
				assert.True(t, *typed.ReplayAllowed)

				assert.Nil(t, typed.setInformer)
				assert.Empty(t, typed.currentKID)
			},
		},
		"creates strategy without nonce manager if nonce is explicitly disabled": {
			conf: map[string]any{
				"max_age":        "1m",
				"nonce_required": false,
			},
			assert: func(t *testing.T, strategy PoPStrategy, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, strategy)

				typed, ok := strategy.(*DPoPStrategy)
				require.True(t, ok)

				assert.Equal(t, time.Minute, typed.MaxAge)

				require.NotNil(t, typed.RequireNonce)
				assert.False(t, *typed.RequireNonce)

				assert.Nil(t, typed.setInformer)
				assert.Empty(t, typed.currentKID)
			},
		},
		"creates strategy with nonce manager if nonce is required": {
			conf: map[string]any{
				"max_age":        "1m",
				"nonce_required": true,
			},
			setup: func(
				t *testing.T,
				appCtx *app.ContextMock,
				resolver *secretsmocks.ResolverMock,
			) {
				t.Helper()

				appCtx.EXPECT().
					Config().
					Return(&config.Configuration{
						MasterKey: &config.Secret{
							Source:   "master-keys",
							Selector: "key-1",
						},
					})

				appCtx.EXPECT().
					SecretResolver().
					Return(resolver)

				handle := secretsmocks.NewSecretSetHandleMock(t)
				handle.EXPECT().
					OnUpdate(mock.Anything).
					Return()

				resolver.EXPECT().
					SecretSet(secrets.Reference{Source: "master-keys"}).
					Return(handle, nil)
			},
			assert: func(t *testing.T, strategy PoPStrategy, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, strategy)

				typed, ok := strategy.(*DPoPStrategy)
				require.True(t, ok)

				assert.Equal(t, time.Minute, typed.MaxAge)

				require.NotNil(t, typed.RequireNonce)
				assert.True(t, *typed.RequireNonce)

				require.NotNil(t, typed.setInformer)
				assert.Equal(t, "key-1", typed.currentKID)
			},
		},
		"uses last selector path segment as current key id": {
			conf: map[string]any{
				"nonce_required": true,
			},
			setup: func(
				t *testing.T,
				appCtx *app.ContextMock,
				resolver *secretsmocks.ResolverMock,
			) {
				t.Helper()

				appCtx.EXPECT().
					Config().
					Return(&config.Configuration{
						MasterKey: &config.Secret{
							Source:   "master-keys",
							Selector: "dpop/key-1",
						},
					})

				appCtx.EXPECT().
					SecretResolver().
					Return(resolver)

				handle := secretsmocks.NewSecretSetHandleMock(t)
				handle.EXPECT().
					OnUpdate(mock.Anything).
					Return()

				resolver.EXPECT().
					SecretSet(secrets.Reference{
						Source:   "master-keys",
						Selector: "dpop",
					}).
					Return(handle, nil)
			},
			assert: func(t *testing.T, strategy PoPStrategy, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, strategy)

				typed, ok := strategy.(*DPoPStrategy)
				require.True(t, ok)

				require.NotNil(t, typed.RequireNonce)
				assert.True(t, *typed.RequireNonce)

				require.NotNil(t, typed.setInformer)
				assert.Equal(t, "key-1", typed.currentKID)
			},
		},
		"returns configuration error if unknown property is configured": {
			conf: map[string]any{
				"unknown": "value",
			},
			assert: func(t *testing.T, _ PoPStrategy, err error) {
				t.Helper()

				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed decoding DPoP config")
			},
		},
		"returns configuration error if max age cannot be decoded": {
			conf: map[string]any{
				"max_age": "not-a-duration",
			},
			assert: func(t *testing.T, _ PoPStrategy, err error) {
				t.Helper()

				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed decoding DPoP config")
			},
		},
		"returns configuration error if nonce is required but master key is missing": {
			conf: map[string]any{
				"nonce_required": true,
			},
			setup: func(
				t *testing.T,
				appCtx *app.ContextMock,
				_ *secretsmocks.ResolverMock,
			) {
				t.Helper()

				appCtx.EXPECT().
					Config().
					Return(&config.Configuration{})
			},
			assert: func(t *testing.T, _ PoPStrategy, err error) {
				t.Helper()

				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "master_key is not configured")
			},
		},
		"returns configuration error if nonce manager informer cannot be created": {
			conf: map[string]any{
				"nonce_required": true,
			},
			setup: func(
				t *testing.T,
				appCtx *app.ContextMock,
				resolver *secretsmocks.ResolverMock,
			) {
				t.Helper()

				appCtx.EXPECT().
					Config().
					Return(&config.Configuration{
						MasterKey: &config.Secret{
							Source:   "master-keys",
							Selector: "key-1",
						},
					})

				appCtx.EXPECT().
					SecretResolver().
					Return(resolver)

				resolver.EXPECT().
					SecretSet(secrets.Reference{Source: "master-keys"}).
					Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, _ PoPStrategy, err error) {
				t.Helper()

				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed creating nonce manager secret set informer")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			appCtx := app.NewContextMock(t)
			resolver := secretsmocks.NewResolverMock(t)

			appCtx.EXPECT().
				DecoderFactory().
				Return(encoding.NewDecoderFactory(nil))

			if tc.setup != nil {
				tc.setup(t, appCtx, resolver)
			}

			strategy, err := newDPoPStrategy(appCtx, tc.conf)

			tc.assert(t, strategy, err)
		})
	}
}

func TestDPoPStrategyMerge(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		strategy *DPoPStrategy
		other    PoPStrategy
		assert   func(t *testing.T, merged PoPStrategy)
	}{
		"returns receiver if other is nil": {
			strategy: &DPoPStrategy{
				MaxAge:        time.Minute,
				RequireNonce:  new(true),
				ReplayAllowed: new(true),
				currentKID:    "1",
				setInformer:   &secrets.SecretSetInformer[nonceManager]{},
			},
			assert: func(t *testing.T, merged PoPStrategy) {
				t.Helper()

				typed, ok := merged.(*DPoPStrategy)
				require.True(t, ok)

				assert.Equal(t, time.Minute, typed.MaxAge)
				require.NotNil(t, typed.RequireNonce)
				assert.True(t, *typed.RequireNonce)
				require.NotNil(t, typed.ReplayAllowed)
				assert.True(t, *typed.ReplayAllowed)
				assert.Equal(t, "1", typed.currentKID)
				assert.NotNil(t, typed.setInformer)
			},
		},
		"returns receiver if other has different strategy type": {
			strategy: &DPoPStrategy{
				MaxAge: time.Minute,
			},
			other: noopPoPStrategy{},
			assert: func(t *testing.T, merged PoPStrategy) {
				t.Helper()

				typed, ok := merged.(*DPoPStrategy)
				require.True(t, ok)
				assert.Equal(t, time.Minute, typed.MaxAge)
			},
		},
		"keeps explicitly disabled nonce requirement": {
			strategy: &DPoPStrategy{
				MaxAge:        time.Minute,
				RequireNonce:  new(false),
				ReplayAllowed: new(false),
			},
			other: &DPoPStrategy{
				MaxAge:        2 * time.Minute,
				RequireNonce:  new(true),
				ReplayAllowed: new(true),
				currentKID:    "1",
				setInformer:   &secrets.SecretSetInformer[nonceManager]{},
			},
			assert: func(t *testing.T, merged PoPStrategy) {
				t.Helper()

				typed, ok := merged.(*DPoPStrategy)
				require.True(t, ok)

				assert.Equal(t, time.Minute, typed.MaxAge)
				require.NotNil(t, typed.RequireNonce)
				assert.False(t, *typed.RequireNonce)
				require.NotNil(t, typed.ReplayAllowed)
				assert.False(t, *typed.ReplayAllowed)
				assert.Empty(t, typed.currentKID)
				assert.Nil(t, typed.setInformer)
			},
		},
		"keeps explicitly enabled nonce requirement": {
			strategy: &DPoPStrategy{
				MaxAge:        time.Minute,
				RequireNonce:  new(true),
				ReplayAllowed: new(true),
				currentKID:    "1",
				setInformer:   &secrets.SecretSetInformer[nonceManager]{},
			},
			other: &DPoPStrategy{
				MaxAge:        2 * time.Minute,
				RequireNonce:  new(false),
				ReplayAllowed: new(false),
			},
			assert: func(t *testing.T, merged PoPStrategy) {
				t.Helper()

				typed, ok := merged.(*DPoPStrategy)
				require.True(t, ok)

				assert.Equal(t, time.Minute, typed.MaxAge)
				require.NotNil(t, typed.RequireNonce)
				assert.True(t, *typed.RequireNonce)
				require.NotNil(t, typed.ReplayAllowed)
				assert.True(t, *typed.ReplayAllowed)
				assert.Equal(t, "1", typed.currentKID)
				assert.NotNil(t, typed.setInformer)
			},
		},
		"uses nonce manager from other if nonce requirement is inherited": {
			strategy: &DPoPStrategy{},
			other: &DPoPStrategy{
				MaxAge:        2 * time.Minute,
				RequireNonce:  new(true),
				ReplayAllowed: new(false),
				currentKID:    "1",
				setInformer:   &secrets.SecretSetInformer[nonceManager]{},
			},
			assert: func(t *testing.T, merged PoPStrategy) {
				t.Helper()

				typed, ok := merged.(*DPoPStrategy)
				require.True(t, ok)

				assert.Equal(t, 2*time.Minute, typed.MaxAge)

				require.NotNil(t, typed.RequireNonce)
				assert.True(t, *typed.RequireNonce)

				require.NotNil(t, typed.ReplayAllowed)
				assert.False(t, *typed.ReplayAllowed)

				assert.Equal(t, "1", typed.currentKID)
				assert.NotNil(t, typed.setInformer)
			},
		},
		"uses values from other for zero values": {
			strategy: &DPoPStrategy{},
			other: &DPoPStrategy{
				MaxAge:        2 * time.Minute,
				RequireNonce:  new(false),
				ReplayAllowed: new(false),
				currentKID:    "1",
				setInformer:   &secrets.SecretSetInformer[nonceManager]{},
			},
			assert: func(t *testing.T, merged PoPStrategy) {
				t.Helper()

				typed, ok := merged.(*DPoPStrategy)
				require.True(t, ok)

				assert.Equal(t, 2*time.Minute, typed.MaxAge)
				require.NotNil(t, typed.RequireNonce)
				assert.False(t, *typed.RequireNonce)
				require.NotNil(t, typed.ReplayAllowed)
				assert.False(t, *typed.ReplayAllowed)
				assert.Empty(t, typed.currentKID)
				assert.Nil(t, typed.setInformer)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.strategy.Merge(tc.other))
		})
	}
}

func TestDPoPStrategyAssert(t *testing.T) {
	t.Parallel()

	const rawToken = "access-token"

	now := time.Now().UTC()
	leeway := 10 * time.Second
	allowedAlgorithms := []jose.SignatureAlgorithm{jose.ES256, jose.HS256}

	key := newDPoPTestKey(t)
	jkt := dpopTestJWKThumbprint(t, key)

	hash := sha256.Sum256(stringx.ToBytes(rawToken))

	validProof := newDPoPProof(t, dpopProofConfig{
		headerKey:       key,
		signingKey:      key,
		rawToken:        rawToken,
		method:          http.MethodGet,
		uri:             "https://api.example.com/resource",
		issuedAt:        now.Add(-10 * time.Second),
		jti:             "jti",
		algorithm:       jose.ES256,
		typeHeader:      "dpop+jwt",
		includeJWK:      true,
		accessTokenHash: base64.RawURLEncoding.EncodeToString(hash[:]),
	})

	for uc, tc := range map[string]struct {
		conf  map[string]any
		token *Token
		setup func(
			t *testing.T,
			appCtx *app.ContextMock,
			resolver *secretsmocks.ResolverMock,
			ctx *pipelineMocks.ContextMock,
			cch *cacheMocks.CacheMock,
		)
		assert func(t *testing.T, err error)
	}{
		"accepts valid proof": {
			conf: map[string]any{
				"max_age":        "1m",
				"replay_allowed": true,
			},
			token: &Token{
				Raw:  rawToken,
				Type: TypeDPoP,
				Claims: Claims{
					Confirmation: &Confirmation{
						JWKThumbprint: jkt,
					},
				},
			},
			setup: func(
				t *testing.T,
				_ *app.ContextMock,
				_ *secretsmocks.ResolverMock,
				ctx *pipelineMocks.ContextMock,
				_ *cacheMocks.CacheMock,
			) {
				t.Helper()

				requestFunctions := pipelineMocks.NewRequestFunctionsMock(t)
				requestFunctions.EXPECT().Header("DPoP").Return(validProof)

				parsedURL, err := url.Parse("https://api.example.com/resource?foo=bar#fragment")
				require.NoError(t, err)

				ctx.EXPECT().Context().Return(t.Context())
				ctx.EXPECT().Request().Return(&pipeline.Request{
					Method:           http.MethodGet,
					URL:              &pipeline.URL{URL: *parsedURL},
					RequestFunctions: requestFunctions,
				})
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"fails if confirmation is missing": {
			conf: map[string]any{},
			token: &Token{
				Raw:  rawToken,
				Type: TypeDPoP,
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				var target *InvalidDPoPProofError
				require.ErrorAs(t, err, &target)
				assert.Equal(t, "proof of possession is required", target.message)
			},
		},
		"fails if token type is missing": {
			conf: map[string]any{"max_age": "1m"},
			token: &Token{
				Raw: rawToken,
				Claims: Claims{
					Confirmation: &Confirmation{JWKThumbprint: jkt},
				},
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				var target *InvalidDPoPProofError
				require.ErrorAs(t, err, &target)
				assert.Equal(t, "malformed token type - DPoP expected", target.message)
			},
		},
		"accepts dpop token type from introspection claims": {
			conf: map[string]any{"replay_allowed": true},
			token: &Token{
				Raw: rawToken,
				Claims: Claims{
					TokenType: TypeDPoP,
					Confirmation: &Confirmation{
						JWKThumbprint: jkt,
					},
				},
			},
			setup: func(
				t *testing.T,
				_ *app.ContextMock,
				_ *secretsmocks.ResolverMock,
				ctx *pipelineMocks.ContextMock,
				_ *cacheMocks.CacheMock,
			) {
				t.Helper()

				requestFunctions := pipelineMocks.NewRequestFunctionsMock(t)
				requestFunctions.EXPECT().Header("DPoP").Return(validProof)

				parsedURL, err := url.Parse("https://api.example.com/resource?foo=bar#fragment")
				require.NoError(t, err)

				ctx.EXPECT().Context().Return(t.Context())
				ctx.EXPECT().Request().Return(&pipeline.Request{
					Method:           http.MethodGet,
					URL:              &pipeline.URL{URL: *parsedURL},
					RequestFunctions: requestFunctions,
				})
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"fails if authorization token type is not dpop": {
			conf: map[string]any{},
			token: &Token{
				Raw:  rawToken,
				Type: TypeBearer,
				Claims: Claims{
					Confirmation: &Confirmation{JWKThumbprint: jkt},
				},
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				var target *InvalidDPoPProofError
				require.ErrorAs(t, err, &target)
				assert.Equal(t, "malformed token type - DPoP expected", target.message)
			},
		},
		"fails if introspection token type is not dpop": {
			conf: map[string]any{
				"max_age": "1m",
			},
			token: &Token{
				Raw: rawToken,
				Claims: Claims{
					TokenType: TypeBearer,
					Confirmation: &Confirmation{
						JWKThumbprint: jkt,
					},
				},
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				var target *InvalidDPoPProofError
				require.ErrorAs(t, err, &target)
				assert.Equal(t, "malformed token type - DPoP expected", target.message)
			},
		},
		"fails if confirmation thumbprint is missing": {
			conf: map[string]any{
				"max_age": "1m",
			},
			token: &Token{
				Raw:  rawToken,
				Type: TypeDPoP,
				Claims: Claims{
					Confirmation: &Confirmation{},
				},
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				var target *InvalidDPoPProofError
				require.ErrorAs(t, err, &target)
				assert.Equal(t, "no JWT thumbprint present", target.message)
			},
		},
		"fails if proof is missing": {
			conf: map[string]any{
				"max_age": "1m",
			},
			token: &Token{
				Raw:  rawToken,
				Type: TypeDPoP,
				Claims: Claims{
					Confirmation: &Confirmation{JWKThumbprint: jkt},
				},
			},
			setup: func(
				t *testing.T,
				_ *app.ContextMock,
				_ *secretsmocks.ResolverMock,
				ctx *pipelineMocks.ContextMock,
				_ *cacheMocks.CacheMock,
			) {
				t.Helper()

				requestFunctions := pipelineMocks.NewRequestFunctionsMock(t)
				requestFunctions.EXPECT().Header("DPoP").Return("")

				ctx.EXPECT().Request().Return(&pipeline.Request{
					RequestFunctions: requestFunctions,
				})
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				var target *InvalidDPoPProofError
				require.ErrorAs(t, err, &target)
				assert.Equal(t, "proof is missing", target.message)
			},
		},
		"fails if proof cannot be parsed": {
			conf: map[string]any{
				"max_age": "1m",
			},
			token: &Token{
				Raw:  rawToken,
				Type: TypeDPoP,
				Claims: Claims{
					Confirmation: &Confirmation{JWKThumbprint: jkt},
				},
			},
			setup: func(
				t *testing.T,
				_ *app.ContextMock,
				_ *secretsmocks.ResolverMock,
				ctx *pipelineMocks.ContextMock,
				_ *cacheMocks.CacheMock,
			) {
				t.Helper()

				requestFunctions := pipelineMocks.NewRequestFunctionsMock(t)
				requestFunctions.EXPECT().Header("DPoP").Return("invalid")

				ctx.EXPECT().Request().Return(&pipeline.Request{
					RequestFunctions: requestFunctions,
				})
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				var target *InvalidDPoPProofError
				require.ErrorAs(t, err, &target)
				assert.Equal(t, "failed to parse proof", target.message)
			},
		},
		"fails with algorithms if proof algorithm is not allowed": {
			conf: map[string]any{
				"max_age": "1m",
			},
			token: &Token{
				Raw:  rawToken,
				Type: TypeDPoP,
				Claims: Claims{
					Confirmation: &Confirmation{JWKThumbprint: jkt},
				},
			},
			setup: func(
				t *testing.T,
				_ *app.ContextMock,
				_ *secretsmocks.ResolverMock,
				ctx *pipelineMocks.ContextMock,
				_ *cacheMocks.CacheMock,
			) {
				t.Helper()

				es384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)

				hash := sha256.Sum256(stringx.ToBytes(rawToken))

				proof := newDPoPProof(t, dpopProofConfig{
					headerKey:       es384Key,
					signingKey:      es384Key,
					rawToken:        rawToken,
					method:          http.MethodGet,
					uri:             "https://api.example.com/resource",
					issuedAt:        now.Add(-10 * time.Second),
					jti:             "jti",
					algorithm:       jose.ES384,
					typeHeader:      "dpop+jwt",
					includeJWK:      true,
					accessTokenHash: base64.RawURLEncoding.EncodeToString(hash[:]),
				})

				requestFunctions := pipelineMocks.NewRequestFunctionsMock(t)
				requestFunctions.EXPECT().Header("DPoP").Return(proof)

				ctx.EXPECT().Request().Return(&pipeline.Request{
					RequestFunctions: requestFunctions,
				})
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				var target *InvalidDPoPProofError
				require.ErrorAs(t, err, &target)
				assert.Equal(t, "algorithm is not allowed", target.message)
				assert.Equal(t, []jose.SignatureAlgorithm{jose.ES256}, target.algorithms)
			},
		},
		"fails if typ header is invalid": {
			conf: map[string]any{
				"max_age": "1m",
			},
			token: &Token{
				Raw:  rawToken,
				Type: TypeDPoP,
				Claims: Claims{
					Confirmation: &Confirmation{JWKThumbprint: jkt},
				},
			},
			setup: func(
				t *testing.T,
				_ *app.ContextMock,
				_ *secretsmocks.ResolverMock,
				ctx *pipelineMocks.ContextMock,
				_ *cacheMocks.CacheMock,
			) {
				t.Helper()

				hash := sha256.Sum256(stringx.ToBytes(rawToken))

				proof := newDPoPProof(t, dpopProofConfig{
					headerKey:       key,
					signingKey:      key,
					rawToken:        rawToken,
					method:          http.MethodGet,
					uri:             "https://api.example.com/resource",
					issuedAt:        now.Add(-10 * time.Second),
					jti:             "jti",
					algorithm:       jose.ES256,
					typeHeader:      "jwt",
					includeJWK:      true,
					accessTokenHash: base64.RawURLEncoding.EncodeToString(hash[:]),
				})

				requestFunctions := pipelineMocks.NewRequestFunctionsMock(t)
				requestFunctions.EXPECT().Header("DPoP").Return(proof)

				ctx.EXPECT().Request().Return(&pipeline.Request{
					RequestFunctions: requestFunctions,
				})
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				var target *InvalidDPoPProofError
				require.ErrorAs(t, err, &target)
				assert.Equal(t, "invalid typ header", target.message)
			},
		},
		"fails if jwk header is missing": {
			conf: map[string]any{
				"max_age": "1m",
			},
			token: &Token{
				Raw:  rawToken,
				Type: TypeDPoP,
				Claims: Claims{
					Confirmation: &Confirmation{JWKThumbprint: jkt},
				},
			},
			setup: func(
				t *testing.T,
				_ *app.ContextMock,
				_ *secretsmocks.ResolverMock,
				ctx *pipelineMocks.ContextMock,
				_ *cacheMocks.CacheMock,
			) {
				t.Helper()

				hash := sha256.Sum256(stringx.ToBytes(rawToken))

				proof := newDPoPProof(t, dpopProofConfig{
					headerKey:       key,
					signingKey:      key,
					rawToken:        rawToken,
					method:          http.MethodGet,
					uri:             "https://api.example.com/resource",
					issuedAt:        now.Add(-10 * time.Second),
					jti:             "jti",
					algorithm:       jose.ES256,
					typeHeader:      "dpop+jwt",
					includeJWK:      false,
					accessTokenHash: base64.RawURLEncoding.EncodeToString(hash[:]),
				})

				requestFunctions := pipelineMocks.NewRequestFunctionsMock(t)
				requestFunctions.EXPECT().Header("DPoP").Return(proof)

				ctx.EXPECT().Request().Return(&pipeline.Request{
					RequestFunctions: requestFunctions,
				})
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				var target *InvalidDPoPProofError
				require.ErrorAs(t, err, &target)
				assert.Equal(t, "no JWK present", target.message)
			},
		},
		"fails if proof key does not match access token binding": {
			conf: map[string]any{
				"max_age": "1m",
			},
			token: &Token{
				Raw:  rawToken,
				Type: TypeDPoP,
				Claims: Claims{
					Confirmation: &Confirmation{
						JWKThumbprint: dpopTestJWKThumbprint(t, newDPoPTestKey(t)),
					},
				},
			},
			setup: func(
				t *testing.T,
				_ *app.ContextMock,
				_ *secretsmocks.ResolverMock,
				ctx *pipelineMocks.ContextMock,
				_ *cacheMocks.CacheMock,
			) {
				t.Helper()

				requestFunctions := pipelineMocks.NewRequestFunctionsMock(t)
				requestFunctions.EXPECT().Header("DPoP").Return(validProof)

				ctx.EXPECT().Request().Return(&pipeline.Request{
					RequestFunctions: requestFunctions,
				})
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				var target *InvalidDPoPProofError
				require.ErrorAs(t, err, &target)
				assert.Equal(t, "proof key does not match access token binding", target.message)
			},
		},
		"fails if proof signature cannot be verified": {
			conf: map[string]any{
				"max_age": "1m",
			},
			token: &Token{
				Raw:  rawToken,
				Type: TypeDPoP,
				Claims: Claims{
					Confirmation: &Confirmation{JWKThumbprint: jkt},
				},
			},
			setup: func(
				t *testing.T,
				_ *app.ContextMock,
				_ *secretsmocks.ResolverMock,
				ctx *pipelineMocks.ContextMock,
				_ *cacheMocks.CacheMock,
			) {
				t.Helper()

				hash := sha256.Sum256(stringx.ToBytes(rawToken))

				proof := newDPoPProof(t, dpopProofConfig{
					headerKey:       key,
					signingKey:      newDPoPTestKey(t),
					rawToken:        rawToken,
					method:          http.MethodGet,
					uri:             "https://api.example.com/resource",
					issuedAt:        now.Add(-10 * time.Second),
					jti:             "jti",
					algorithm:       jose.ES256,
					typeHeader:      "dpop+jwt",
					includeJWK:      true,
					accessTokenHash: base64.RawURLEncoding.EncodeToString(hash[:]),
				})

				requestFunctions := pipelineMocks.NewRequestFunctionsMock(t)
				requestFunctions.EXPECT().Header("DPoP").Return(proof)

				ctx.EXPECT().Request().Return(&pipeline.Request{
					RequestFunctions: requestFunctions,
				})
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				var target *InvalidDPoPProofError
				require.ErrorAs(t, err, &target)
				assert.Equal(t, "failed to verify signature", target.message)
			},
		},
		"delegates validation errors from proof claims": {
			conf: map[string]any{
				"max_age": "1m",
			},
			token: &Token{
				Raw:  rawToken,
				Type: TypeDPoP,
				Claims: Claims{
					Confirmation: &Confirmation{JWKThumbprint: jkt},
				},
			},
			setup: func(
				t *testing.T,
				_ *app.ContextMock,
				_ *secretsmocks.ResolverMock,
				ctx *pipelineMocks.ContextMock,
				cch *cacheMocks.CacheMock,
			) {
				t.Helper()

				hash := sha256.Sum256(stringx.ToBytes(rawToken))

				proof := newDPoPProof(t, dpopProofConfig{
					headerKey:       key,
					signingKey:      key,
					rawToken:        rawToken,
					method:          http.MethodPost,
					uri:             "https://api.example.com/resource",
					issuedAt:        now.Add(-10 * time.Second),
					jti:             "jti",
					algorithm:       jose.ES256,
					typeHeader:      "dpop+jwt",
					includeJWK:      true,
					accessTokenHash: base64.RawURLEncoding.EncodeToString(hash[:]),
				})

				requestFunctions := pipelineMocks.NewRequestFunctionsMock(t)
				requestFunctions.EXPECT().Header("DPoP").Return(proof)

				parsedURL, err := url.Parse("https://api.example.com/resource?foo=bar#fragment")
				require.NoError(t, err)

				ctx.EXPECT().Request().Return(&pipeline.Request{
					Method:           http.MethodGet,
					URL:              &pipeline.URL{URL: *parsedURL},
					RequestFunctions: requestFunctions,
				})
				ctx.EXPECT().Context().Return(cache.WithContext(t.Context(), cch))

				hash = sha256.Sum256(stringx.ToBytes("jti"))

				cch.EXPECT().
					Get(mock.Anything, "dpop:jti:"+base64.RawURLEncoding.EncodeToString(hash[:])).
					Return(nil, cache.ErrNoEntry)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				var target *InvalidDPoPProofError
				require.ErrorAs(t, err, &target)
				assert.Equal(t, "htm does not match request method", target.message)
			},
		},
		"returns internal error if nonce is required and master key is not available": {
			conf: map[string]any{
				"max_age":        "1m",
				"nonce_required": true,
			},
			token: &Token{
				Raw:  rawToken,
				Type: TypeDPoP,
				Claims: Claims{
					Confirmation: &Confirmation{JWKThumbprint: jkt},
				},
			},
			setup: func(
				t *testing.T,
				appCtx *app.ContextMock,
				resolver *secretsmocks.ResolverMock,
				ctx *pipelineMocks.ContextMock,
				_ *cacheMocks.CacheMock,
			) {
				t.Helper()

				appCtx.EXPECT().
					Config().
					Return(&config.Configuration{
						MasterKey: &config.Secret{
							Source:   "master-keys",
							Selector: "key-1",
						},
					})

				appCtx.EXPECT().
					SecretResolver().
					Return(resolver)

				handle := secretsmocks.NewSecretSetHandleMock(t)
				handle.EXPECT().
					OnUpdate(mock.Anything).
					Return()

				resolver.EXPECT().
					SecretSet(secrets.Reference{Source: "master-keys"}).
					Return(handle, nil)

				requestFunctions := pipelineMocks.NewRequestFunctionsMock(t)
				requestFunctions.EXPECT().Header("DPoP").Return(validProof)

				ctx.EXPECT().Request().Return(&pipeline.Request{
					RequestFunctions: requestFunctions,
				})
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.ErrorIs(t, err, pipeline.ErrInternal)
				require.ErrorContains(t, err, "master key is not available")
			},
		},
		"accepts proof older than leeway but younger than default max age": {
			conf: map[string]any{
				"replay_allowed": true,
			},
			token: &Token{
				Raw:  rawToken,
				Type: TypeDPoP,
				Claims: Claims{
					Confirmation: &Confirmation{
						JWKThumbprint: jkt,
					},
				},
			},
			setup: func(
				t *testing.T,
				_ *app.ContextMock,
				_ *secretsmocks.ResolverMock,
				ctx *pipelineMocks.ContextMock,
				_ *cacheMocks.CacheMock,
			) {
				t.Helper()

				hash := sha256.Sum256(stringx.ToBytes(rawToken))

				proof := newDPoPProof(t, dpopProofConfig{
					headerKey:       key,
					signingKey:      key,
					rawToken:        rawToken,
					method:          http.MethodGet,
					uri:             "https://api.example.com/resource",
					issuedAt:        now.Add(-30 * time.Second),
					jti:             "jti",
					algorithm:       jose.ES256,
					typeHeader:      "dpop+jwt",
					includeJWK:      true,
					accessTokenHash: base64.RawURLEncoding.EncodeToString(hash[:]),
				})

				requestFunctions := pipelineMocks.NewRequestFunctionsMock(t)
				requestFunctions.EXPECT().Header("DPoP").Return(proof)

				parsedURL, err := url.Parse("https://api.example.com/resource?foo=bar#fragment")
				require.NoError(t, err)

				ctx.EXPECT().Context().Return(t.Context())
				ctx.EXPECT().Request().Return(&pipeline.Request{
					Method:           http.MethodGet,
					URL:              &pipeline.URL{URL: *parsedURL},
					RequestFunctions: requestFunctions,
				})
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"fails if proof uses symmetric embedded jwk even if algorithm is allowed": {
			conf: map[string]any{
				"max_age": "1m",
			},
			token: &Token{
				Raw:  rawToken,
				Type: TypeDPoP,
				Claims: Claims{
					Confirmation: &Confirmation{JWKThumbprint: jkt},
				},
			},
			setup: func(
				t *testing.T,
				_ *app.ContextMock,
				_ *secretsmocks.ResolverMock,
				ctx *pipelineMocks.ContextMock,
				_ *cacheMocks.CacheMock,
			) {
				t.Helper()

				key := stringx.ToBytes("0123456789abcdef0123456789abcdef")
				hash := sha256.Sum256(stringx.ToBytes(rawToken))

				proof := newDPoPProof(t, dpopProofConfig{
					headerKey:       key,
					signingKey:      key,
					rawToken:        rawToken,
					method:          http.MethodGet,
					uri:             "https://api.example.com/resource",
					issuedAt:        now.Add(-10 * time.Second),
					jti:             "jti",
					algorithm:       jose.HS256,
					typeHeader:      "dpop+jwt",
					includeJWK:      true,
					accessTokenHash: base64.RawURLEncoding.EncodeToString(hash[:]),
				})

				requestFunctions := pipelineMocks.NewRequestFunctionsMock(t)
				requestFunctions.EXPECT().Header("DPoP").Return(proof)

				ctx.EXPECT().Request().Return(&pipeline.Request{
					RequestFunctions: requestFunctions,
				})
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				var target *InvalidDPoPProofError
				require.ErrorAs(t, err, &target)
				assert.Equal(t, "failed to parse proof", target.message)
				require.ErrorContains(t, err, "invalid embedded jwk")
				require.ErrorContains(t, err, "must be public key")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			appCtx := app.NewContextMock(t)
			resolver := secretsmocks.NewResolverMock(t)
			ctx := pipelineMocks.NewContextMock(t)
			cch := cacheMocks.NewCacheMock(t)

			appCtx.EXPECT().
				DecoderFactory().
				Return(encoding.NewDecoderFactory(nil))

			if tc.setup != nil {
				tc.setup(t, appCtx, resolver, ctx, cch)
			}

			strategy, err := newDPoPStrategy(appCtx, tc.conf)
			require.NoError(t, err)

			err = strategy.Assert(ctx, tc.token, leeway, allowedAlgorithms)

			tc.assert(t, err)
		})
	}
}

func TestDPoPStrategyCreateNonceManager(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		strategy *DPoPStrategy
		secrets  []secrets.Secret
		assert   func(t *testing.T, mgr nonceManager, err error)
	}{
		"creates nonce manager from symmetric secrets": {
			strategy: &DPoPStrategy{
				currentKID: "key-2",
			},
			secrets: []secrets.Secret{
				secrettypes.NewSymmetricKeySecret(
					"key-1",
					"key-1",
					"HS256",
					stringx.ToBytes("0123456789abcdef0123456789abcdef"),
				),
				secrettypes.NewSymmetricKeySecret(
					"key-2",
					"key-2",
					"HS256",
					stringx.ToBytes("abcdef0123456789abcdef0123456789"),
				),
			},
			assert: func(t *testing.T, mgr nonceManager, err error) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "key-2", mgr.current.KID)
				assert.Equal(t, stringx.ToBytes("abcdef0123456789abcdef0123456789"), mgr.current.Value)
				require.Len(t, mgr.keys, 2)
			},
		},
		"ignores non symmetric secrets": {
			strategy: &DPoPStrategy{
				currentKID: "key-1",
			},
			secrets: []secrets.Secret{
				secrettypes.NewStringSecret("api-key", "secret"),
				secrettypes.NewSymmetricKeySecret(
					"key-1",
					"key-1",
					"HS256",
					stringx.ToBytes("0123456789abcdef0123456789abcdef"),
				),
			},
			assert: func(t *testing.T, mgr nonceManager, err error) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "key-1", mgr.current.KID)
				require.Len(t, mgr.keys, 1)
			},
		},
		"returns configuration error if current key is missing": {
			strategy: &DPoPStrategy{
				currentKID: "missing",
			},
			secrets: []secrets.Secret{
				secrettypes.NewSymmetricKeySecret(
					"key-1",
					"key-1",
					"HS256",
					stringx.ToBytes("0123456789abcdef0123456789abcdef"),
				),
			},
			assert: func(t *testing.T, mgr nonceManager, err error) {
				t.Helper()

				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "current master key not found in key set")
				assert.Empty(t, mgr.current.KID)
			},
		},
		"returns configuration error if no symmetric secrets are present": {
			strategy: &DPoPStrategy{
				currentKID: "key-1",
			},
			secrets: []secrets.Secret{
				secrettypes.NewStringSecret("api-key", "secret"),
			},
			assert: func(t *testing.T, mgr nonceManager, err error) {
				t.Helper()

				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "current master key not found in key set")
				assert.Empty(t, mgr.current.KID)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			mgr, err := tc.strategy.createNonceManager(tc.secrets)

			tc.assert(t, mgr, err)
		})
	}
}

type noopPoPStrategy struct{}

func (s noopPoPStrategy) Assert(pipeline.Context, *Token, time.Duration, []jose.SignatureAlgorithm) error {
	return nil
}

func (s noopPoPStrategy) Merge(PoPStrategy) PoPStrategy {
	return s
}

type dpopProofConfig struct {
	headerKey       any
	signingKey      any
	rawToken        string
	method          string
	uri             string
	issuedAt        time.Time
	jti             string
	algorithm       jose.SignatureAlgorithm
	typeHeader      string
	includeJWK      bool
	accessTokenHash string
}

func newDPoPProof(t *testing.T, conf dpopProofConfig) string {
	t.Helper()

	options := (&jose.SignerOptions{}).WithType(jose.ContentType(conf.typeHeader))
	if conf.includeJWK {
		headerKey := conf.headerKey
		if publicKeyProvider, ok := conf.headerKey.(interface{ Public() crypto.PublicKey }); ok {
			headerKey = publicKeyProvider.Public()
		}

		options = options.WithHeader("jwk", jose.JSONWebKey{
			Key:       headerKey,
			Algorithm: string(conf.algorithm),
			Use:       "sig",
		})
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: conf.algorithm,
			Key:       conf.signingKey,
		},
		options,
	)
	require.NoError(t, err)

	proof, err := jwt.Signed(signer).
		Claims(DPoPClaims{
			HTTPMethod:      conf.method,
			HTTPURI:         conf.uri,
			AccessTokenHash: conf.accessTokenHash,
			IssuedAt:        conf.issuedAt,
			JTI:             conf.jti,
		}).
		Serialize()
	require.NoError(t, err)

	return proof
}

func newDPoPTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	return key
}

func dpopTestJWKThumbprint(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()

	jkt, err := (&jose.JSONWebKey{Key: key.Public()}).Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	return base64.RawURLEncoding.EncodeToString(jkt)
}
