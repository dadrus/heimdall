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

package authstrategy

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
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
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x"
)

func TestApplyClientCredentialsStrategy(t *testing.T) {
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

	for _, tc := range []struct {
		uc             string
		strategy       *ClientCredentialsStrategy
		configureMocks func(t *testing.T, cch *mocks.CacheMock)
		assertRequest  RequestAsserter
		buildResponse  ResponseBuilder
		assert         func(t *testing.T, err error, tokenEndpointCalled bool, req *http.Request)
	}{
		{
			uc:       "reusing response from cache",
			strategy: &ClientCredentialsStrategy{},
			configureMocks: func(t *testing.T, cch *mocks.CacheMock) {
				t.Helper()

				cch.EXPECT().Get(mock.Anything).Return("foobar")
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool, req *http.Request) {
				t.Helper()

				require.NoError(t, err)
				assert.False(t, tokenEndpointCalled)
				assert.Equal(t, "Bearer foobar", req.Header.Get("Authorization"))
			},
		},
		{
			uc:       "cache entry of wrong type and no ttl in issued token",
			strategy: &ClientCredentialsStrategy{TokenURL: srv.URL, ClientID: "foo", ClientSecret: "bar"},
			configureMocks: func(t *testing.T, cch *mocks.CacheMock) {
				t.Helper()

				cch.EXPECT().Get(mock.Anything).Return(10)
				cch.EXPECT().Delete(mock.Anything)
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				val, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(req.Header.Get("Authorization"), "Basic "))
				assert.NoError(t, err)

				clientIDAndSecret := strings.Split(string(val), ":")
				assert.Equal(t, "foo", clientIDAndSecret[0])
				assert.Equal(t, "bar", clientIDAndSecret[1])

				assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
				assert.Equal(t, "application/json", req.Header.Get("Accept-Type"))
				assert.Equal(t, "client_credentials", req.FormValue("grant_type"))
				assert.Empty(t, req.FormValue("scope"))
			},
			buildResponse: func(t *testing.T) (any, int) {
				t.Helper()

				return &TokenSuccessfulResponse{
					AccessToken: "barfoo",
					TokenType:   "Foo",
				}, http.StatusOK
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool, req *http.Request) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, tokenEndpointCalled)
				assert.Equal(t, "Bearer barfoo", req.Header.Get("Authorization"))
			},
		},
		{
			uc: "ttl not configured, no cache entry and token has expires_in claim",
			strategy: &ClientCredentialsStrategy{
				Header: &HeaderConfig{
					Name:   "Authorization",
					Scheme: "Bar",
				},
				TokenURL:     srv.URL,
				ClientID:     "bar",
				ClientSecret: "foo",
			},
			configureMocks: func(t *testing.T, cch *mocks.CacheMock) {
				t.Helper()

				cch.EXPECT().Get(mock.Anything).Return(nil)
				cch.EXPECT().Set(mock.Anything, "barfoo", 5*time.Minute-5*time.Second).Return()
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				val, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(req.Header.Get("Authorization"), "Basic "))
				assert.NoError(t, err)

				clientIDAndSecret := strings.Split(string(val), ":")
				assert.Equal(t, "bar", clientIDAndSecret[0])
				assert.Equal(t, "foo", clientIDAndSecret[1])

				assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
				assert.Equal(t, "application/json", req.Header.Get("Accept-Type"))
				assert.Equal(t, "client_credentials", req.FormValue("grant_type"))
				assert.Empty(t, req.FormValue("scope"))
			},
			buildResponse: func(t *testing.T) (any, int) {
				t.Helper()

				return &TokenSuccessfulResponse{
					AccessToken: "barfoo",
					TokenType:   "Foo",
					ExpiresIn:   int64((5 * time.Minute).Seconds()),
				}, http.StatusOK
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool, req *http.Request) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, tokenEndpointCalled)
				assert.Equal(t, "Bar barfoo", req.Header.Get("Authorization"))
			},
		},
		{
			uc:       "error while unmarshalling successful response",
			strategy: &ClientCredentialsStrategy{TokenURL: srv.URL, ClientID: "bar", ClientSecret: "foo"},
			configureMocks: func(t *testing.T, cch *mocks.CacheMock) {
				t.Helper()

				cch.EXPECT().Get(mock.Anything).Return(nil)
			},
			assertRequest: func(t *testing.T, req *http.Request) { t.Helper() },
			buildResponse: func(t *testing.T) (any, int) {
				t.Helper()

				return "foo", http.StatusOK
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool, req *http.Request) {
				t.Helper()

				assert.True(t, tokenEndpointCalled)
				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Empty(t, req.Header)
			},
		},
		{
			uc:       "error while unmarshalling error response",
			strategy: &ClientCredentialsStrategy{TokenURL: srv.URL, ClientID: "bar", ClientSecret: "foo"},
			configureMocks: func(t *testing.T, cch *mocks.CacheMock) {
				t.Helper()

				cch.EXPECT().Get(mock.Anything).Return(nil)
			},
			assertRequest: func(t *testing.T, req *http.Request) { t.Helper() },
			buildResponse: func(t *testing.T) (any, int) {
				t.Helper()

				return "foo", http.StatusBadRequest
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool, req *http.Request) {
				t.Helper()

				assert.True(t, tokenEndpointCalled)
				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Empty(t, req.Header)
			},
		},
		{
			uc:       "error while sending request",
			strategy: &ClientCredentialsStrategy{TokenURL: "http://127.0.0.1:11111", ClientID: "bar", ClientSecret: "foo"},
			configureMocks: func(t *testing.T, cch *mocks.CacheMock) {
				t.Helper()

				cch.EXPECT().Get(mock.Anything).Return(nil)
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool, req *http.Request) {
				t.Helper()

				assert.False(t, tokenEndpointCalled)
				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrCommunication)
				assert.Empty(t, req.Header)
			},
		},
		{
			uc: "full configuration, no cache hit and token has expires_in claim",
			strategy: &ClientCredentialsStrategy{
				Header: &HeaderConfig{
					Name:   "X-My-Header",
					Scheme: "Foo",
				},
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

				cch.EXPECT().Get(mock.Anything).Return(nil)
				cch.EXPECT().Set(mock.Anything, "foobar", 3*time.Minute).Return()
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				val, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(req.Header.Get("Authorization"), "Basic "))
				assert.NoError(t, err)

				clientIDAndSecret := strings.Split(string(val), ":")
				assert.Equal(t, "bar", clientIDAndSecret[0])
				assert.Equal(t, "foo", clientIDAndSecret[1])

				assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
				assert.Equal(t, "application/json", req.Header.Get("Accept-Type"))
				assert.Equal(t, "client_credentials", req.FormValue("grant_type"))
				scopes := strings.Split(req.FormValue("scope"), " ")
				assert.Len(t, scopes, 2)
				assert.Contains(t, scopes, "baz")
				assert.Contains(t, scopes, "zab")
			},
			buildResponse: func(t *testing.T) (any, int) {
				t.Helper()

				return &TokenSuccessfulResponse{
					AccessToken: "foobar",
					TokenType:   "Foo",
					ExpiresIn:   int64((5 * time.Minute).Seconds()),
				}, http.StatusOK
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool, req *http.Request) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, tokenEndpointCalled)
				assert.Equal(t, "Foo foobar", req.Header.Get("X-My-Header"))
			},
		},
		{
			uc: "disabled cache",
			strategy: &ClientCredentialsStrategy{
				Header: &HeaderConfig{
					Name:   "X-My-Header",
					Scheme: "Foo",
				},
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

				val, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(req.Header.Get("Authorization"), "Basic "))
				assert.NoError(t, err)

				clientIDAndSecret := strings.Split(string(val), ":")
				assert.Equal(t, "bar", clientIDAndSecret[0])
				assert.Equal(t, "foo", clientIDAndSecret[1])

				assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
				assert.Equal(t, "application/json", req.Header.Get("Accept-Type"))
				assert.Equal(t, "client_credentials", req.FormValue("grant_type"))
				scopes := strings.Split(req.FormValue("scope"), " ")
				assert.Len(t, scopes, 2)
				assert.Contains(t, scopes, "baz")
				assert.Contains(t, scopes, "zab")
			},
			buildResponse: func(t *testing.T) (any, int) {
				t.Helper()

				return &TokenSuccessfulResponse{
					AccessToken: "foobar",
					TokenType:   "Foo",
					ExpiresIn:   int64((5 * time.Minute).Seconds()),
				}, http.StatusOK
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool, req *http.Request) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, tokenEndpointCalled)
				assert.Equal(t, "Foo foobar", req.Header.Get("X-My-Header"))
			},
		},
		{
			uc: "custom cache ttl and no expires_in in token",
			strategy: &ClientCredentialsStrategy{
				Header: &HeaderConfig{
					Name:   "X-My-Header",
					Scheme: "Foo",
				},
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

				cch.EXPECT().Get(mock.Anything).Return(nil)
				cch.EXPECT().Set(mock.Anything, "foobar", 3*time.Minute).Return()
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				val, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(req.Header.Get("Authorization"), "Basic "))
				assert.NoError(t, err)

				clientIDAndSecret := strings.Split(string(val), ":")
				assert.Equal(t, "bar", clientIDAndSecret[0])
				assert.Equal(t, "foo", clientIDAndSecret[1])

				assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
				assert.Equal(t, "application/json", req.Header.Get("Accept-Type"))
				assert.Equal(t, "client_credentials", req.FormValue("grant_type"))
				scopes := strings.Split(req.FormValue("scope"), " ")
				assert.Len(t, scopes, 2)
				assert.Contains(t, scopes, "baz")
				assert.Contains(t, scopes, "zab")
			},
			buildResponse: func(t *testing.T) (any, int) {
				t.Helper()

				return &TokenSuccessfulResponse{
					AccessToken: "foobar",
					TokenType:   "Foo",
				}, http.StatusOK
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool, req *http.Request) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, tokenEndpointCalled)
				assert.Equal(t, "Foo foobar", req.Header.Get("X-My-Header"))
			},
		},
		{
			uc: "using request_body authentication strategy",
			strategy: &ClientCredentialsStrategy{
				TokenURL:     srv.URL,
				ClientID:     "bar foo",
				ClientSecret: "foo bar",
				AuthMethod:   authMethodRequestBody,
				TTL: func() *time.Duration {
					ttl := 3 * time.Minute

					return &ttl
				}(),
				Scopes: []string{"baz", "zab"},
			},
			configureMocks: func(t *testing.T, cch *mocks.CacheMock) {
				t.Helper()

				cch.EXPECT().Get(mock.Anything).Return(nil)
				cch.EXPECT().Set(mock.Anything, "foobar", 3*time.Minute).Return()
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
				assert.Equal(t, "application/json", req.Header.Get("Accept-Type"))
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

				return &TokenSuccessfulResponse{
					AccessToken: "foobar",
					TokenType:   "Foo",
				}, http.StatusOK
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool, req *http.Request) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, tokenEndpointCalled)
				assert.Equal(t, "Bearer foobar", req.Header.Get("Authorization"))
			},
		},
		{
			uc: "misbehaving server on error",
			strategy: &ClientCredentialsStrategy{
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

				val, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(req.Header.Get("Authorization"), "Basic "))
				assert.NoError(t, err)

				clientIDAndSecret := strings.Split(string(val), ":")
				assert.Equal(t, "bar", clientIDAndSecret[0])
				assert.Equal(t, "foo", clientIDAndSecret[1])

				assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
				assert.Equal(t, "application/json", req.Header.Get("Accept-Type"))
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
			assert: func(t *testing.T, err error, tokenEndpointCalled bool, req *http.Request) {
				t.Helper()

				assert.True(t, tokenEndpointCalled)
				require.Error(t, err)
				assert.Contains(t, err.Error(), "invalid_request")
				assert.Empty(t, req.Header)
			},
		},
		{
			uc: "misbehaving server on error, response code unexpected",
			strategy: &ClientCredentialsStrategy{
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
			assert: func(t *testing.T, err error, tokenEndpointCalled bool, req *http.Request) {
				t.Helper()

				assert.True(t, tokenEndpointCalled)
				require.Error(t, err)
				assert.Contains(t, err.Error(), "unexpected response code: 403")
				assert.Empty(t, req.Header)
			},
		},
		{
			uc: "compliant server on error",
			strategy: &ClientCredentialsStrategy{
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

				cch.EXPECT().Get(mock.Anything).Return(nil)
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				val, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(req.Header.Get("Authorization"), "Basic "))
				assert.NoError(t, err)

				clientIDAndSecret := strings.Split(string(val), ":")
				assert.Equal(t, "bar", clientIDAndSecret[0])
				assert.Equal(t, "foo", clientIDAndSecret[1])

				assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
				assert.Equal(t, "application/json", req.Header.Get("Accept-Type"))
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
			assert: func(t *testing.T, err error, tokenEndpointCalled bool, req *http.Request) {
				t.Helper()

				assert.True(t, tokenEndpointCalled)
				require.Error(t, err)
				assert.Contains(t, err.Error(), "invalid_request")
				assert.Empty(t, req.Header)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			endpointCalled = false
			configureMocks := x.IfThenElse(tc.configureMocks != nil,
				tc.configureMocks,
				func(t *testing.T, _ *mocks.CacheMock) { t.Helper() },
			)
			assertRequest = x.IfThenElse(tc.assertRequest != nil,
				tc.assertRequest,
				func(t *testing.T, req *http.Request) { t.Helper() },
			)
			buildResponse = tc.buildResponse

			cch := mocks.NewCacheMock(t)
			ctx := cache.WithContext(context.Background(), cch)

			configureMocks(t, cch)

			req := &http.Request{Header: http.Header{}}

			// WHEN
			err := tc.strategy.Apply(ctx, req)

			// THEN
			tc.assert(t, err, endpointCalled, req)
		})
	}
}

func TestClientCredentialsStrategyHash(t *testing.T) {
	t.Parallel()

	// GIVEN
	s1 := &ClientCredentialsStrategy{ClientID: "Foo", ClientSecret: "Bar"}
	s2 := &ClientCredentialsStrategy{ClientID: "Baz", ClientSecret: "Bar"}

	// WHEN
	hash1 := s1.Hash()
	hash2 := s2.Hash()

	// THEN
	assert.NotEmpty(t, hash1)
	assert.NotEmpty(t, hash2)
	assert.NotEqual(t, hash1, hash2)
}
