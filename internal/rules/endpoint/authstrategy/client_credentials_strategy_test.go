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
	"crypto"
	"crypto/rand"
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
	"github.com/dadrus/heimdall/internal/x"
)

func TestApplyClientCredentialsStrategy(t *testing.T) {
	t.Parallel()

	// GIVEN
	clientID := "test-client"
	clientSecret := "test-secret"
	scopes := []string{"foo", "bar"}

	var (
		receivedAuthorization string
		receivedContentType   string
		receivedAcceptType    string
		receivedGrantType     string
		receivedScope         string
		setAccessToken        string
		setExpiresIn          int64
		endpointCalled        bool
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		endpointCalled = true

		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)

			return
		}
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		receivedAuthorization = r.Header.Get("Authorization")
		receivedContentType = r.Header.Get("Content-Type")
		receivedAcceptType = r.Header.Get("Accept-Type")
		receivedGrantType = r.FormValue("grant_type")
		receivedScope = r.FormValue("scope")

		type response struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			ExpiresIn   int64  `json:"expires_in"`
		}

		blk := make([]byte, 16)
		_, err := rand.Read(blk)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		setAccessToken = base64.StdEncoding.EncodeToString(crypto.SHA256.New().Sum(blk))
		setExpiresIn = 30
		resp := response{
			AccessToken: setAccessToken,
			TokenType:   "Bearer",
			ExpiresIn:   setExpiresIn,
		}

		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)

			return
		}
		rawResp, err := json.MarshalContext(r.Context(), &resp)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		w.Header().Set("Content-Type", receivedAcceptType)
		w.Header().Set("Content-Length", strconv.Itoa(len(rawResp)))

		_, err = w.Write(rawResp)
		assert.NoError(t, err)
	}))
	defer srv.Close()

	defaultCacheSetup := func(t *testing.T, cch *mocks.CacheMock, key string) {
		t.Helper()

		cch.EXPECT().Get(key).Return(nil)

		var resp *tokenEndpointResponse

		cch.EXPECT().Set(key,
			mock.MatchedBy(func(val *tokenEndpointResponse) bool {
				resp = val

				return true
			}),
			mock.MatchedBy(func(val time.Duration) bool {
				require.NotNil(t, resp)
				assert.Equal(t, time.Duration(resp.ExpiresIn-defaultCacheLeeway)*time.Second, val)

				return true
			}))
	}

	for _, tc := range []struct {
		uc         string
		strategy   ClientCredentialsStrategy
		setupCache func(t *testing.T, cch *mocks.CacheMock, key string)
		assert     func(t *testing.T, err error, req *http.Request)
	}{
		{
			uc: "without cache hit",
			strategy: ClientCredentialsStrategy{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				Scopes:       scopes,
				TokenURL:     srv.URL,
			},
			assert: func(t *testing.T, err error, req *http.Request) {
				t.Helper()

				assert.NoError(t, err)

				require.True(t, endpointCalled)

				val, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(receivedAuthorization, "Basic "))
				assert.NoError(t, err)

				clientIDAndSecret := strings.Split(string(val), ":")
				assert.Equal(t, clientID, clientIDAndSecret[0])
				assert.Equal(t, clientSecret, clientIDAndSecret[1])

				assert.Equal(t, "application/x-www-form-urlencoded", receivedContentType)
				assert.Equal(t, "application/json", receivedAcceptType)
				assert.Equal(t, "client_credentials", receivedGrantType)
				assert.Equal(t, strings.Join(scopes, " "), receivedScope)

				assert.Equal(t, "Bearer "+setAccessToken, req.Header.Get("Authorization"))
			},
		},
		{
			uc: "with not valid cache hit",
			strategy: ClientCredentialsStrategy{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				Scopes:       scopes,
				TokenURL:     srv.URL,
			},
			setupCache: func(t *testing.T, cch *mocks.CacheMock, key string) {
				t.Helper()

				var resp *tokenEndpointResponse

				cch.EXPECT().Get(key).Return("foo")
				cch.EXPECT().Delete(key)
				cch.EXPECT().Set(key,
					mock.MatchedBy(func(val *tokenEndpointResponse) bool {
						resp = val

						return true
					}),
					mock.MatchedBy(func(val time.Duration) bool {
						require.NotNil(t, resp)
						assert.Equal(t, time.Duration(resp.ExpiresIn-defaultCacheLeeway)*time.Second, val)

						return true
					}))
			},
			assert: func(t *testing.T, err error, req *http.Request) {
				t.Helper()

				assert.NoError(t, err)

				require.True(t, endpointCalled)

				val, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(receivedAuthorization, "Basic "))
				assert.NoError(t, err)

				clientIDAndSecret := strings.Split(string(val), ":")
				assert.Equal(t, clientID, clientIDAndSecret[0])
				assert.Equal(t, clientSecret, clientIDAndSecret[1])

				assert.Equal(t, "application/x-www-form-urlencoded", receivedContentType)
				assert.Equal(t, "application/json", receivedAcceptType)
				assert.Equal(t, "client_credentials", receivedGrantType)
				assert.Equal(t, strings.Join(scopes, " "), receivedScope)

				assert.Equal(t, "Bearer "+setAccessToken, req.Header.Get("Authorization"))
			},
		},
		{
			uc: "with valid cache hit",
			strategy: ClientCredentialsStrategy{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				Scopes:       scopes,
				TokenURL:     srv.URL,
			},
			setupCache: func(t *testing.T, cch *mocks.CacheMock, key string) {
				t.Helper()

				cached := &tokenEndpointResponse{
					AccessToken: "FooBar",
					ExpiresIn:   time.Now().Unix() + 100,
					TokenType:   "Baz",
				}

				cch.EXPECT().Get(key).Return(cached)
			},
			assert: func(t *testing.T, err error, req *http.Request) {
				t.Helper()

				assert.NoError(t, err)
				assert.False(t, endpointCalled)

				assert.Equal(t, "Baz FooBar", req.Header.Get("Authorization"))
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			//  GIVEN
			endpointCalled = false

			setupCache := x.IfThenElse(tc.setupCache != nil, tc.setupCache, defaultCacheSetup)

			cacheKey := tc.strategy.calculateCacheKey()
			cch := mocks.NewCacheMock(t)
			setupCache(t, cch, cacheKey)

			ctx := cache.WithContext(context.Background(), cch)

			req := &http.Request{Header: http.Header{}}

			// WHEN
			err := tc.strategy.Apply(ctx, req)

			// THEN
			tc.assert(t, err, req)
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
