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
	"errors"
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
	"github.com/dadrus/heimdall/internal/rules/oauth2/clientcredentials"
	"github.com/dadrus/heimdall/internal/x"
)

func TestApplyClientCredentialsStrategy(t *testing.T) {
	t.Parallel()

	type (
		RequestAsserter func(t *testing.T, req *http.Request)
		ResponseBuilder func(t *testing.T) (any, int)

		Token struct {
			AccessToken string `json:"access_token,omitempty"`
			TokenType   string `json:"token_type,omitempty"`
			ExpiresIn   int64  `json:"expires_in,omitempty"`
			Scope       string `json:"scope,omitempty"`
		}
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
		require.NoError(t, err)
	}))
	defer srv.Close()

	for _, tc := range []struct {
		uc             string
		strategy       *OAuth2ClientCredentials
		configureMocks func(t *testing.T, cch *mocks.CacheMock)
		assertRequest  RequestAsserter
		buildResponse  ResponseBuilder
		assert         func(t *testing.T, err error, tokenEndpointCalled bool, req *http.Request)
	}{
		{
			uc:       "reusing response from cache, no custom header",
			strategy: &OAuth2ClientCredentials{},
			configureMocks: func(t *testing.T, cch *mocks.CacheMock) {
				t.Helper()

				rawData, err := json.Marshal(clientcredentials.TokenInfo{
					AccessToken: "foobar", TokenType: "Bearer",
				})
				require.NoError(t, err)

				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(rawData, nil)
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool, req *http.Request) {
				t.Helper()

				require.NoError(t, err)
				assert.False(t, tokenEndpointCalled)
				assert.Equal(t, "Bearer foobar", req.Header.Get("Authorization"))
			},
		},
		{
			uc: "error while unmarshalling successful response",
			strategy: &OAuth2ClientCredentials{
				Config: clientcredentials.Config{
					TokenURL: srv.URL, ClientID: "bar", ClientSecret: "foo",
				},
			},
			configureMocks: func(t *testing.T, cch *mocks.CacheMock) {
				t.Helper()

				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, errors.New("no cache entry"))
			},
			assertRequest: func(t *testing.T, _ *http.Request) { t.Helper() },
			buildResponse: func(t *testing.T) (any, int) {
				t.Helper()

				return "foo", http.StatusOK
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool, req *http.Request) {
				t.Helper()

				assert.True(t, tokenEndpointCalled)
				require.Error(t, err)
				assert.Empty(t, req.Header)
			},
		},
		{
			uc: "full configuration, no cache hit and token has expires_in claim",
			strategy: &OAuth2ClientCredentials{
				Config: clientcredentials.Config{
					TokenURL:     srv.URL,
					ClientID:     "bar",
					ClientSecret: "foo",
					TTL: func() *time.Duration {
						ttl := 3 * time.Minute

						return &ttl
					}(),
					Scopes: []string{"baz", "zab"},
				},
				Header: &HeaderConfig{Name: "X-My-Header", Scheme: "Foo"},
			},
			configureMocks: func(t *testing.T, cch *mocks.CacheMock) {
				t.Helper()

				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, errors.New("no cache entry"))
				cch.EXPECT().Set(mock.Anything, mock.Anything, mock.Anything, 3*time.Minute).Return(nil)
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				val, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(req.Header.Get("Authorization"), "Basic "))
				require.NoError(t, err)

				clientIDAndSecret := strings.Split(string(val), ":")
				assert.Equal(t, "bar", clientIDAndSecret[0])
				assert.Equal(t, "foo", clientIDAndSecret[1])

				assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
				assert.Equal(t, "client_credentials", req.FormValue("grant_type"))
				scopes := strings.Split(req.FormValue("scope"), " ")
				assert.Len(t, scopes, 2)
				assert.Contains(t, scopes, "baz")
				assert.Contains(t, scopes, "zab")
			},
			buildResponse: func(t *testing.T) (any, int) {
				t.Helper()

				return &Token{
					AccessToken: "foobar",
					TokenType:   "Bar",
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
	} {
		t.Run(tc.uc, func(t *testing.T) {
			endpointCalled = false
			configureMocks := x.IfThenElse(tc.configureMocks != nil,
				tc.configureMocks,
				func(t *testing.T, _ *mocks.CacheMock) { t.Helper() },
			)
			assertRequest = x.IfThenElse(tc.assertRequest != nil,
				tc.assertRequest,
				func(t *testing.T, _ *http.Request) { t.Helper() },
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
