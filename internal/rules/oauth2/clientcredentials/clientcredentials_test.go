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

package clientcredentials

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/x"
)

func TestClientCredentialsAuthStrategyApply(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		strategy *clientCredentialsAuthStrategy
		assert   func(t *testing.T, req, original *http.Request)
	}{
		"basic auth": {
			strategy: &clientCredentialsAuthStrategy{
				ClientID:     "foo",
				ClientSecret: "bar",
			},
			assert: func(t *testing.T, req, original *http.Request) {
				t.Helper()

				user, password, ok := req.BasicAuth()
				require.True(t, ok)
				assert.Equal(t, "foo", user)
				assert.Equal(t, "bar", password)

				_, _, ok = original.BasicAuth()
				assert.False(t, ok)
			},
		},
		"request body": {
			strategy: &clientCredentialsAuthStrategy{
				ClientID:     "foo",
				ClientSecret: "bar",
				AuthMethod:   AuthMethodRequestBody,
			},
			assert: func(t *testing.T, req, original *http.Request) {
				t.Helper()

				data, err := io.ReadAll(req.Body)
				require.NoError(t, err)

				values, err := url.ParseQuery(string(data))
				require.NoError(t, err)

				assert.Equal(t, "client_credentials", values.Get("grant_type"))
				assert.Equal(t, "foo", values.Get("client_id"))
				assert.Equal(t, "bar", values.Get("client_secret"))

				// Direct fields must only have changed on the shallow copy.
				assert.NotEqual(t, original.ContentLength, req.ContentLength)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			original, err := http.NewRequestWithContext(
				t.Context(),
				http.MethodPost,
				"https://example.com",
				strings.NewReader("grant_type=client_credentials"),
			)
			require.NoError(t, err)

			req := *original

			err = tc.strategy.Apply(&req)
			require.NoError(t, err)

			tc.assert(t, &req, original)
		})
	}
}

func TestClientCredentialsAuthStrategyHash(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		s1, s2      clientCredentialsAuthStrategy
		expectEqual bool
	}{
		"same configuration": {
			s1: clientCredentialsAuthStrategy{
				ClientID:     "Foo",
				ClientSecret: "Bar",
				AuthMethod:   AuthMethodBasicAuth,
			},
			s2: clientCredentialsAuthStrategy{
				ClientID:     "Foo",
				ClientSecret: "Bar",
				AuthMethod:   AuthMethodBasicAuth,
			},
			expectEqual: true,
		},
		"default and explicit basic auth method": {
			s1: clientCredentialsAuthStrategy{
				ClientID:     "Foo",
				ClientSecret: "Bar",
			},
			s2: clientCredentialsAuthStrategy{
				ClientID:     "Foo",
				ClientSecret: "Bar",
				AuthMethod:   AuthMethodBasicAuth,
			},
			expectEqual: true,
		},
		"different client ids": {
			s1: clientCredentialsAuthStrategy{
				ClientID:     "Foo",
				ClientSecret: "Bar",
			},
			s2: clientCredentialsAuthStrategy{
				ClientID:     "Baz",
				ClientSecret: "Bar",
			},
		},
		"different client secrets": {
			s1: clientCredentialsAuthStrategy{
				ClientID:     "Foo",
				ClientSecret: "Bar",
			},
			s2: clientCredentialsAuthStrategy{
				ClientID:     "Foo",
				ClientSecret: "Baz",
			},
		},
		"different authentication methods": {
			s1: clientCredentialsAuthStrategy{
				ClientID:     "Foo",
				ClientSecret: "Bar",
				AuthMethod:   AuthMethodBasicAuth,
			},
			s2: clientCredentialsAuthStrategy{
				ClientID:     "Foo",
				ClientSecret: "Bar",
				AuthMethod:   AuthMethodRequestBody,
			},
		},
		"field boundaries are preserved": {
			s1: clientCredentialsAuthStrategy{
				ClientID:     "a",
				ClientSecret: "bc",
			},
			s2: clientCredentialsAuthStrategy{
				ClientID:     "ab",
				ClientSecret: "c",
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			hash1 := tc.s1.Hash()
			hash2 := tc.s2.Hash()

			assert.NotEmpty(t, hash1)
			assert.NotEmpty(t, hash2)

			if tc.expectEqual {
				assert.Equal(t, hash1, hash2)
			} else {
				assert.NotEqual(t, hash1, hash2)
			}
		})
	}
}

func TestClientCredentialsToken(t *testing.T) {
	t.Parallel()

	type (
		RequestAsserter func(t *testing.T, req *http.Request)
		ResponseBuilder func(t *testing.T) (any, int)
	)

	var (
		endpointCalled bool
		assertRequest  RequestAsserter
		buildResponse  ResponseBuilder
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		endpointCalled = true

		if req.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)

			return
		}

		if err := req.ParseForm(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		assertRequest(t, req)

		resp, code := buildResponse(t)

		rawResp, err := json.MarshalContext(req.Context(), resp)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(rawResp)))

		w.WriteHeader(code)
		_, err = w.Write(rawResp)
		assert.NoError(t, err)
	}))
	defer srv.Close()

	for uc, tc := range map[string]struct {
		cfg            *Config
		configureMocks func(t *testing.T, cch *mocks.CacheMock)
		assertRequest  RequestAsserter
		buildResponse  ResponseBuilder
		assert         func(t *testing.T, err error, tokenEndpointCalled bool, token *TokenInfo)
	}{
		"reusing response from cache": {
			cfg: &Config{},
			configureMocks: func(t *testing.T, cch *mocks.CacheMock) {
				t.Helper()

				rawData, err := json.Marshal(&TokenInfo{TokenType: "Bearer", AccessToken: "foobar"})
				require.NoError(t, err)

				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(rawData, nil)
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool, token *TokenInfo) {
				t.Helper()

				require.NoError(t, err)
				assert.False(t, tokenEndpointCalled)
				assert.Equal(t, "Bearer", token.TokenType)
				assert.Equal(t, "foobar", token.AccessToken)
				assert.Empty(t, token.RefreshToken)
				assert.Empty(t, token.Scopes)
				assert.Equal(t, time.Time{}, token.Expiry)
			},
		},
		"ttl not configured, no cache entry and token has expires_in claim": {
			cfg: &Config{
				TokenURL:     srv.URL,
				ClientID:     "bar",
				ClientSecret: "foo",
			},
			configureMocks: func(t *testing.T, cch *mocks.CacheMock) {
				t.Helper()

				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, assert.AnError)
				cch.EXPECT().Set(mock.Anything, mock.Anything, mock.Anything,
					mock.MatchedBy(func(ttl time.Duration) bool {
						return ttl.Round(time.Second) == 5*time.Minute-5*time.Second
					}),
				).Return(nil)
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				val, err := base64.StdEncoding.DecodeString(
					strings.TrimPrefix(req.Header.Get("Authorization"), "Basic "),
				)
				require.NoError(t, err)

				clientIDAndSecret := strings.Split(string(val), ":")
				assert.Equal(t, "bar", clientIDAndSecret[0])
				assert.Equal(t, "foo", clientIDAndSecret[1])

				assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
				assert.Equal(t, "application/json", req.Header.Get("Accept"))
				assert.Equal(t, "client_credentials", req.FormValue("grant_type"))
				assert.Empty(t, req.FormValue("scope"))
			},
			buildResponse: func(t *testing.T) (any, int) {
				t.Helper()

				return &TokenInfoResponse{
					AccessToken: "barfoo",
					TokenType:   "Foo",
					ExpiresIn:   int64((5 * time.Minute).Seconds()),
				}, http.StatusOK
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool, token *TokenInfo) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, tokenEndpointCalled)
				assert.Equal(t, "Foo", token.TokenType)
				assert.Equal(t, "barfoo", token.AccessToken)
				assert.Equal(t, 5*time.Minute, time.Until(token.Expiry).Round(time.Second))
			},
		},
		"error while unmarshalling successful response": {
			cfg: &Config{TokenURL: srv.URL, ClientID: "bar", ClientSecret: "foo"},
			configureMocks: func(t *testing.T, cch *mocks.CacheMock) {
				t.Helper()

				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, assert.AnError)
			},
			assertRequest: func(t *testing.T, _ *http.Request) { t.Helper() },
			buildResponse: func(t *testing.T) (any, int) {
				t.Helper()

				return "foo", http.StatusOK
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool, _ *TokenInfo) {
				t.Helper()

				assert.True(t, tokenEndpointCalled)
				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrInternal)
			},
		},
		"error while unmarshalling error response": {
			cfg: &Config{TokenURL: srv.URL, ClientID: "bar", ClientSecret: "foo"},
			configureMocks: func(t *testing.T, cch *mocks.CacheMock) {
				t.Helper()

				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, assert.AnError)
			},
			assertRequest: func(t *testing.T, _ *http.Request) { t.Helper() },
			buildResponse: func(t *testing.T) (any, int) {
				t.Helper()

				return "foo", http.StatusBadRequest
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool, _ *TokenInfo) {
				t.Helper()

				assert.True(t, tokenEndpointCalled)
				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrCommunication)
			},
		},
		"error while sending request": {
			cfg: &Config{
				TokenURL:     "http://127.0.0.1:11111",
				ClientID:     "bar",
				ClientSecret: "foo",
			},
			configureMocks: func(t *testing.T, cch *mocks.CacheMock) {
				t.Helper()

				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool, _ *TokenInfo) {
				t.Helper()

				assert.False(t, tokenEndpointCalled)
				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrCommunication)
			},
		},
		"full configuration, no cache hit with scopes and expires_in": {
			cfg: &Config{
				TokenURL:     srv.URL,
				ClientID:     "bar",
				ClientSecret: "foo",
				TTL: func() *time.Duration {
					ttl := 3 * time.Minute

					return &ttl
				}(),
				Scopes: []string{"baz", "zab"},
			},
			configureMocks: func(t *testing.T, cch *mocks.CacheMock) {
				t.Helper()

				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, assert.AnError)
				cch.EXPECT().
					Set(mock.Anything, mock.Anything, mock.Anything, 3*time.Minute).
					Return(nil)
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				val, err := base64.StdEncoding.DecodeString(
					strings.TrimPrefix(req.Header.Get("Authorization"), "Basic "),
				)
				require.NoError(t, err)

				clientIDAndSecret := strings.Split(string(val), ":")
				assert.Equal(t, "bar", clientIDAndSecret[0])
				assert.Equal(t, "foo", clientIDAndSecret[1])

				assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
				assert.Equal(t, "application/json", req.Header.Get("Accept"))
				assert.Equal(t, "client_credentials", req.FormValue("grant_type"))
				scopes := strings.Split(req.FormValue("scope"), " ")
				assert.Len(t, scopes, 2)
				assert.Contains(t, scopes, "baz")
				assert.Contains(t, scopes, "zab")
			},
			buildResponse: func(t *testing.T) (any, int) {
				t.Helper()

				type TokenInfoResponseWithExtraClaims struct {
					TokenInfoResponse

					Foo string `json:"foo"`
					Bar int    `json:"bar"`
				}

				return &TokenInfoResponseWithExtraClaims{
					TokenInfoResponse: TokenInfoResponse{
						AccessToken: "foobar",
						TokenType:   "Foo",
						ExpiresIn:   int64((5 * time.Minute).Seconds()),
						Scope:       "baz zab",
					},
					Foo: "bar",
					Bar: 42,
				}, http.StatusOK
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool, token *TokenInfo) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, tokenEndpointCalled)
				assert.Equal(t, "Foo", token.TokenType)
				assert.Equal(t, "foobar", token.AccessToken)
				assert.Equal(t, 5*time.Minute, time.Until(token.Expiry).Round(time.Second))
				assert.Len(t, token.Scopes, 2)
				assert.Contains(t, token.Scopes, "baz")
				assert.Contains(t, token.Scopes, "zab")
			},
		},
		"disabled cache": {
			cfg: &Config{
				TokenURL:     srv.URL,
				ClientID:     "bar",
				ClientSecret: "foo",
				TTL: func() *time.Duration {
					ttl := 0 * time.Second

					return &ttl
				}(),
				Scopes: []string{"baz", "zab"},
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				val, err := base64.StdEncoding.DecodeString(
					strings.TrimPrefix(req.Header.Get("Authorization"), "Basic "),
				)
				require.NoError(t, err)

				clientIDAndSecret := strings.Split(string(val), ":")
				assert.Equal(t, "bar", clientIDAndSecret[0])
				assert.Equal(t, "foo", clientIDAndSecret[1])

				assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
				assert.Equal(t, "application/json", req.Header.Get("Accept"))
				assert.Equal(t, "client_credentials", req.FormValue("grant_type"))
				scopes := strings.Split(req.FormValue("scope"), " ")
				assert.Len(t, scopes, 2)
				assert.Contains(t, scopes, "baz")
				assert.Contains(t, scopes, "zab")
			},
			buildResponse: func(t *testing.T) (any, int) {
				t.Helper()

				return &TokenInfoResponse{
					AccessToken: "foobar",
					TokenType:   "Foo",
					ExpiresIn:   int64((5 * time.Minute).Seconds()),
				}, http.StatusOK
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool, token *TokenInfo) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, tokenEndpointCalled)
				assert.Equal(t, "Foo", token.TokenType)
				assert.Equal(t, "foobar", token.AccessToken)
			},
		},
		"custom cache ttl and no expires_in in token": {
			cfg: &Config{
				TokenURL:     srv.URL,
				ClientID:     "bar",
				ClientSecret: "foo",
				TTL: func() *time.Duration {
					ttl := 3 * time.Minute

					return &ttl
				}(),
				Scopes: []string{"baz", "zab"},
			},
			configureMocks: func(t *testing.T, cch *mocks.CacheMock) {
				t.Helper()

				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, assert.AnError)
				cch.EXPECT().
					Set(mock.Anything, mock.Anything, mock.Anything, 3*time.Minute).
					Return(nil)
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				val, err := base64.StdEncoding.DecodeString(
					strings.TrimPrefix(req.Header.Get("Authorization"), "Basic "),
				)
				require.NoError(t, err)

				clientIDAndSecret := strings.Split(string(val), ":")
				assert.Equal(t, "bar", clientIDAndSecret[0])
				assert.Equal(t, "foo", clientIDAndSecret[1])

				assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
				assert.Equal(t, "application/json", req.Header.Get("Accept"))
				assert.Equal(t, "client_credentials", req.FormValue("grant_type"))
				scopes := strings.Split(req.FormValue("scope"), " ")
				assert.Len(t, scopes, 2)
				assert.Contains(t, scopes, "baz")
				assert.Contains(t, scopes, "zab")
			},
			buildResponse: func(t *testing.T) (any, int) {
				t.Helper()

				return &TokenInfoResponse{
					AccessToken: "foobar",
					TokenType:   "Foo",
				}, http.StatusOK
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool, token *TokenInfo) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, tokenEndpointCalled)
				assert.Equal(t, "Foo", token.TokenType)
				assert.Equal(t, "foobar", token.AccessToken)
			},
		},
		"using request_body authentication strategy": {
			cfg: &Config{
				TokenURL:     srv.URL,
				ClientID:     "bar foo",
				ClientSecret: "foo bar",
				AuthMethod:   AuthMethodRequestBody,
				TTL: func() *time.Duration {
					ttl := 3 * time.Minute

					return &ttl
				}(),
				Scopes: []string{"baz", "zab"},
			},
			configureMocks: func(t *testing.T, cch *mocks.CacheMock) {
				t.Helper()

				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, assert.AnError)
				cch.EXPECT().
					Set(mock.Anything, mock.Anything, mock.Anything, 3*time.Minute).
					Return(nil)
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
				assert.Equal(t, "application/json", req.Header.Get("Accept"))
				assert.Equal(t, "bar foo", req.FormValue("client_id"))
				assert.Equal(t, "foo bar", req.FormValue("client_secret"))
				assert.Equal(t, "client_credentials", req.FormValue("grant_type"))
				scopes := strings.Split(req.FormValue("scope"), " ")
				assert.Len(t, scopes, 2)
				assert.Contains(t, scopes, "baz")
				assert.Contains(t, scopes, "zab")
			},
			buildResponse: func(t *testing.T) (any, int) {
				t.Helper()

				return &TokenInfoResponse{
					AccessToken: "foobar",
					TokenType:   "Foo",
				}, http.StatusOK
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool, token *TokenInfo) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, tokenEndpointCalled)
				assert.Equal(t, "Foo", token.TokenType)
				assert.Equal(t, "foobar", token.AccessToken)
			},
		},
		"misbehaving server on error": {
			cfg: &Config{
				TokenURL:     srv.URL,
				ClientID:     "bar",
				ClientSecret: "foo",
				TTL: func() *time.Duration {
					ttl := 0 * time.Minute

					return &ttl
				}(),
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				val, err := base64.StdEncoding.DecodeString(
					strings.TrimPrefix(req.Header.Get("Authorization"), "Basic "),
				)
				require.NoError(t, err)

				clientIDAndSecret := strings.Split(string(val), ":")
				assert.Equal(t, "bar", clientIDAndSecret[0])
				assert.Equal(t, "foo", clientIDAndSecret[1])

				assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
				assert.Equal(t, "application/json", req.Header.Get("Accept"))
				assert.Equal(t, "client_credentials", req.FormValue("grant_type"))
			},
			buildResponse: func(t *testing.T) (any, int) {
				t.Helper()

				// the following is not compliant as error is defined otherwise
				// in https://www.rfc-editor.org/rfc/rfc6749#section-5.2
				res, err := json.Marshal(map[string]any{
					"error":             "invalid_request",
					"error_description": "whatever",
				})
				require.NoError(t, err)

				return &TokenErrorResponse{
					ErrorType: string(res),
				}, http.StatusOK
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool, _ *TokenInfo) {
				t.Helper()

				assert.True(t, tokenEndpointCalled)
				require.Error(t, err)
				require.ErrorContains(t, err, "invalid_request")
			},
		},
		"misbehaving server on error, response code unexpected": {
			cfg: &Config{
				TokenURL:     srv.URL,
				ClientID:     "bar",
				ClientSecret: "foo",
				TTL: func() *time.Duration {
					ttl := 0 * time.Minute

					return &ttl
				}(),
			},
			buildResponse: func(t *testing.T) (any, int) {
				t.Helper()

				return &TokenErrorResponse{
					ErrorType:        "invalid_request",
					ErrorDescription: "whatever",
				}, http.StatusForbidden
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool, _ *TokenInfo) {
				t.Helper()

				assert.True(t, tokenEndpointCalled)
				require.Error(t, err)
				require.ErrorContains(t, err, "unexpected response code: 403")
			},
		},
		"compliant server on error ": {
			cfg: &Config{
				TokenURL:     srv.URL,
				ClientID:     "bar",
				ClientSecret: "foo",
				TTL: func() *time.Duration {
					ttl := 3 * time.Minute

					return &ttl
				}(),
			},
			configureMocks: func(t *testing.T, cch *mocks.CacheMock) {
				t.Helper()

				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, assert.AnError)
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				val, err := base64.StdEncoding.DecodeString(
					strings.TrimPrefix(req.Header.Get("Authorization"), "Basic "),
				)
				require.NoError(t, err)

				clientIDAndSecret := strings.Split(string(val), ":")
				assert.Equal(t, "bar", clientIDAndSecret[0])
				assert.Equal(t, "foo", clientIDAndSecret[1])

				assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
				assert.Equal(t, "application/json", req.Header.Get("Accept"))
				assert.Equal(t, "client_credentials", req.FormValue("grant_type"))
			},
			buildResponse: func(t *testing.T) (any, int) {
				t.Helper()

				return &TokenErrorResponse{
					ErrorType:        "invalid_request",
					ErrorDescription: "whatever",
					ErrorURI:         "https://www.rfc-editor.org/rfc/rfc6749#section-5.1",
				}, http.StatusBadRequest
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool, _ *TokenInfo) {
				t.Helper()

				assert.True(t, tokenEndpointCalled)
				require.Error(t, err)
				require.ErrorContains(t, err, "invalid_request")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			endpointCalled = false
			configureMocks := x.IfThenElse(
				tc.configureMocks != nil,
				tc.configureMocks,
				func(t *testing.T, _ *mocks.CacheMock) { t.Helper() },
			)
			assertRequest = x.IfThenElse(
				tc.assertRequest != nil,
				tc.assertRequest,
				func(t *testing.T, _ *http.Request) { t.Helper() },
			)
			buildResponse = tc.buildResponse

			cch := mocks.NewCacheMock(t)
			ctx := cache.WithContext(t.Context(), cch)

			configureMocks(t, cch)

			// WHEN
			token, err := tc.cfg.Token(ctx)

			// THEN
			tc.assert(t, err, endpointCalled, token)
		})
	}
}

func TestClientCredentialsHash(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		c1, c2      *Config
		expectEqual bool
	}{
		"same configuration": {
			c1: &Config{
				TokenURL:     "https://example.com/token",
				ClientID:     "Foo",
				ClientSecret: "Bar",
				Scopes:       []string{"foo", "bar"},
			},
			c2: &Config{
				TokenURL:     "https://example.com/token",
				ClientID:     "Foo",
				ClientSecret: "Bar",
				Scopes:       []string{"foo", "bar"},
			},
			expectEqual: true,
		},
		"default and explicit basic auth method": {
			c1: &Config{
				TokenURL:     "https://example.com/token",
				ClientID:     "Foo",
				ClientSecret: "Bar",
			},
			c2: &Config{
				TokenURL:     "https://example.com/token",
				ClientID:     "Foo",
				ClientSecret: "Bar",
				AuthMethod:   AuthMethodBasicAuth,
			},
			expectEqual: true,
		},
		"different token url": {
			c1: &Config{
				TokenURL:     "https://example.com/token-a",
				ClientID:     "Foo",
				ClientSecret: "Bar",
			},
			c2: &Config{
				TokenURL:     "https://example.com/token-b",
				ClientID:     "Foo",
				ClientSecret: "Bar",
			},
		},
		"different client ids": {
			c1: &Config{
				ClientID:     "Foo",
				ClientSecret: "Bar",
			},
			c2: &Config{
				ClientID:     "Baz",
				ClientSecret: "Bar",
			},
		},
		"different client secrets": {
			c1: &Config{
				ClientID:     "Foo",
				ClientSecret: "Bar",
			},
			c2: &Config{
				ClientID:     "Foo",
				ClientSecret: "Baz",
			},
		},
		"different authentication methods": {
			c1: &Config{
				ClientID:     "Foo",
				ClientSecret: "Bar",
				AuthMethod:   AuthMethodBasicAuth,
			},
			c2: &Config{
				ClientID:     "Foo",
				ClientSecret: "Bar",
				AuthMethod:   AuthMethodRequestBody,
			},
		},
		"field boundaries are preserved": {
			c1: &Config{
				ClientID:     "a",
				ClientSecret: "bc",
			},
			c2: &Config{
				ClientID:     "ab",
				ClientSecret: "c",
			},
		},
		"ambiguous scope sets": {
			c1: &Config{
				ClientID:     "Foo",
				ClientSecret: "Bar",
				Scopes:       []string{"foo", "bar"},
			},
			c2: &Config{
				ClientID:     "Foo",
				ClientSecret: "Bar",
				Scopes:       []string{"foobar"},
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			hash1 := tc.c1.Hash()
			hash2 := tc.c2.Hash()

			assert.NotEmpty(t, hash1)
			assert.NotEmpty(t, hash2)

			if tc.expectEqual {
				assert.Equal(t, hash1, hash2)
			} else {
				assert.NotEqual(t, hash1, hash2)
			}
		})
	}
}

func TestClientCredentialsCalculateCacheKey(t *testing.T) {
	t.Parallel()

	durationPtr := func(value time.Duration) *time.Duration {
		return &value
	}

	for uc, tc := range map[string]struct {
		c1, c2      *Config
		expectEqual bool
	}{
		"same configuration": {
			c1: &Config{
				TokenURL:     "https://example.com/token",
				ClientID:     "client",
				ClientSecret: "secret",
				TTL:          durationPtr(5 * time.Second),
				Scopes:       []string{"foo", "bar"},
			},
			c2: &Config{
				TokenURL:     "https://example.com/token",
				ClientID:     "client",
				ClientSecret: "secret",
				TTL:          durationPtr(5 * time.Second),
				Scopes:       []string{"foo", "bar"},
			},
			expectEqual: true,
		},
		"default and explicit basic auth method": {
			c1: &Config{
				TokenURL:     "https://example.com/token",
				ClientID:     "client",
				ClientSecret: "secret",
			},
			c2: &Config{
				TokenURL:     "https://example.com/token",
				ClientID:     "client",
				ClientSecret: "secret",
				AuthMethod:   AuthMethodBasicAuth,
			},
			expectEqual: true,
		},
		"different authentication method": {
			c1: &Config{
				TokenURL:     "https://example.com/token",
				ClientID:     "client",
				ClientSecret: "secret",
				AuthMethod:   AuthMethodBasicAuth,
			},
			c2: &Config{
				TokenURL:     "https://example.com/token",
				ClientID:     "client",
				ClientSecret: "secret",
				AuthMethod:   AuthMethodRequestBody,
			},
		},
		"different cache ttl": {
			c1: &Config{
				TokenURL:     "https://example.com/token",
				ClientID:     "client",
				ClientSecret: "secret",
				TTL:          durationPtr(5 * time.Second),
			},
			c2: &Config{
				TokenURL:     "https://example.com/token",
				ClientID:     "client",
				ClientSecret: "secret",
				TTL:          durationPtr(15 * time.Second),
			},
		},
		"default and explicit cache ttl": {
			c1: &Config{
				TokenURL:     "https://example.com/token",
				ClientID:     "client",
				ClientSecret: "secret",
			},
			c2: &Config{
				TokenURL:     "https://example.com/token",
				ClientID:     "client",
				ClientSecret: "secret",
				TTL:          durationPtr(5 * time.Second),
			},
		},
		"field boundaries are preserved": {
			c1: &Config{
				TokenURL:     "https://example.com/token",
				ClientID:     "a",
				ClientSecret: "bc",
			},
			c2: &Config{
				TokenURL:     "https://example.com/token",
				ClientID:     "ab",
				ClientSecret: "c",
			},
		},
		"ambiguous scope sets": {
			c1: &Config{
				TokenURL:     "https://example.com/token",
				ClientID:     "client",
				ClientSecret: "secret",
				TTL:          durationPtr(5 * time.Second),
				Scopes:       []string{"foo", "bar"},
			},
			c2: &Config{
				TokenURL:     "https://example.com/token",
				ClientID:     "client",
				ClientSecret: "secret",
				TTL:          durationPtr(5 * time.Second),
				Scopes:       []string{"foobar"},
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			key1 := tc.c1.calculateCacheKey()
			key2 := tc.c2.calculateCacheKey()

			assert.NotEmpty(t, key1)
			assert.NotEmpty(t, key2)

			if tc.expectEqual {
				assert.Equal(t, key1, key2)
			} else {
				assert.NotEqual(t, key1, key2)
			}
		})
	}
}
