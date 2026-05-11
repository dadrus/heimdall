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

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/rules/oauth2/clientcredentials"
	"github.com/dadrus/heimdall/internal/secrets"
	secretsmock "github.com/dadrus/heimdall/internal/secrets/mocks"
	"github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/x"
)

func TestOAuth2ClientCredentialsInit(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		header *headerConfig
		setup  func(t *testing.T, sm *secretsmock.ManagerMock)
		assert func(t *testing.T, err error, cc *OAuth2ClientCredentials)
	}{
		"fails to resolve credentials": {
			setup: func(t *testing.T, sm *secretsmock.ManagerMock) {
				t.Helper()

				sm.EXPECT().ResolveCredentials(mock.Anything, mock.Anything).
					Return(nil, errors.New("boom"))
			},
			assert: func(t *testing.T, err error, cc *OAuth2ClientCredentials) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "failed resolving oauth2 client credentials")

				assert.Nil(t, cc.Hash())
				_, ok := cc.resolver.Get()
				require.False(t, ok)
			},
		},
		"fails decoding credentials": {
			setup: func(t *testing.T, sm *secretsmock.ManagerMock) {
				t.Helper()

				sm.EXPECT().ResolveCredentials(mock.Anything, mock.Anything).
					Return(types.NewCredentials("foo", "bar", map[string]any{
						"foo": "baz",
						"bar": "foo",
					}), nil)
			},
			assert: func(t *testing.T, err error, cc *OAuth2ClientCredentials) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "invalid credentials payload")

				assert.Nil(t, cc.Hash())
				_, ok := cc.resolver.Get()
				require.False(t, ok)
			},
		},
		"succeeds without custom header": {
			setup: func(t *testing.T, sm *secretsmock.ManagerMock) {
				t.Helper()

				sm.EXPECT().Subscribe(mock.Anything, mock.Anything).Return(func() {}, nil)
				sm.EXPECT().ResolveCredentials(mock.Anything, mock.Anything).
					Return(types.NewCredentials("foo", "bar", map[string]any{
						"client_id":     "baz",
						"client_secret": "foo",
					}), nil)
			},
			assert: func(t *testing.T, err error, cc *OAuth2ClientCredentials) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, cc.Header)
				assert.Equal(t, "Authorization", cc.Header.Name)
				assert.Equal(t, "Bearer", cc.Header.Scheme)
				require.NotNil(t, cc.resolver)

				exp := clientcredentials.Config{
					TokenURL:     "https://example.com/token",
					ClientID:     "baz",
					ClientSecret: "foo",
					AuthMethod:   "basic_auth",
					Scopes:       []string{"foo", "bar"},
					TTL:          new(1 * time.Minute),
				}

				val, ok := cc.resolver.Get()
				require.True(t, ok)
				assert.Equal(t, exp, val)
				assert.NotEmpty(t, cc.Hash())
			},
		},
		"succeeds with custom header": {
			header: &headerConfig{Name: "X-My-Header", Scheme: "Foo"},
			setup: func(t *testing.T, sm *secretsmock.ManagerMock) {
				t.Helper()

				sm.EXPECT().Subscribe(mock.Anything, mock.Anything).Return(func() {}, nil)
				sm.EXPECT().ResolveCredentials(mock.Anything, mock.Anything).
					Return(types.NewCredentials("foo", "bar", map[string]any{
						"client_id":     "baz",
						"client_secret": "foo",
					}), nil)
			},
			assert: func(t *testing.T, err error, cc *OAuth2ClientCredentials) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, cc.Header)
				assert.Equal(t, "X-My-Header", cc.Header.Name)
				assert.Equal(t, "Foo", cc.Header.Scheme)
				require.NotNil(t, cc.resolver)

				exp := clientcredentials.Config{
					TokenURL:     "https://example.com/token",
					ClientID:     "baz",
					ClientSecret: "foo",
					AuthMethod:   "basic_auth",
					Scopes:       []string{"foo", "bar"},
					TTL:          new(1 * time.Minute),
				}

				val, ok := cc.resolver.Get()
				require.True(t, ok)
				assert.Equal(t, exp, val)
				assert.NotEmpty(t, cc.Hash())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			secret := config.Secret{Source: "foo", Selector: "bar"}
			sm := secretsmock.NewManagerMock(t)

			tc.setup(t, sm)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().SecretsManager().Return(sm)

			ak := &OAuth2ClientCredentials{
				TokenURL:    "https://example.com/token",
				Credentials: secret,
				AuthMethod:  "basic_auth",
				Scopes:      []string{"foo", "bar"},
				Header:      tc.header,
				TTL:         new(1 * time.Minute),
			}

			// WHEN
			err := ak.init(t.Context(), appCtx)

			// THEN
			tc.assert(t, err, ak)
		})
	}
}

func TestOAuth2ClientCredentialsApply(t *testing.T) {
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
		assert.NoError(t, err)
	}))
	defer srv.Close()

	for uc, tc := range map[string]struct {
		header         *headerConfig
		ttl            *time.Duration
		configureMocks func(t *testing.T, cch *mocks.CacheMock, sm *secretsmock.ManagerMock)
		assertRequest  RequestAsserter
		buildResponse  ResponseBuilder
		assert         func(t *testing.T, err error, tokenEndpointCalled bool, req *http.Request)
	}{
		"reusing response from cache, no custom header": {
			configureMocks: func(t *testing.T, cch *mocks.CacheMock, sm *secretsmock.ManagerMock) {
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
		"error while unmarshalling successful response": {
			configureMocks: func(t *testing.T, cch *mocks.CacheMock, sm *secretsmock.ManagerMock) {
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
		"full configuration, no cache hit and token has expires_in claim": {
			ttl:    new(3 * time.Minute),
			header: &headerConfig{Name: "X-My-Header", Scheme: "Foo"},
			configureMocks: func(t *testing.T, cch *mocks.CacheMock, sm *secretsmock.ManagerMock) {
				t.Helper()

				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, errors.New("no cache entry"))
				cch.EXPECT().Set(mock.Anything, mock.Anything, mock.Anything, 3*time.Minute).Return(nil)
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				val, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(req.Header.Get("Authorization"), "Basic "))
				require.NoError(t, err)

				clientIDAndSecret := strings.Split(string(val), ":")
				assert.Equal(t, "baz", clientIDAndSecret[0])
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
		t.Run(uc, func(t *testing.T) {
			cc := &OAuth2ClientCredentials{
				TokenURL:    srv.URL,
				Credentials: config.Secret{Source: "foo", Selector: "bar"},
				AuthMethod:  "basic_auth",
				Scopes:      []string{"baz", "zab"},
				TTL:         tc.ttl,
				Header:      tc.header,
			}

			cch := mocks.NewCacheMock(t)
			ctx := cache.WithContext(t.Context(), cch)

			ref := secrets.InternalRef(cc.Credentials.Source, cc.Credentials.Selector)
			sm := secretsmock.NewManagerMock(t)
			sm.EXPECT().Subscribe(ref, mock.Anything).Return(func() {}, nil)
			sm.EXPECT().ResolveCredentials(mock.Anything, ref).
				Return(types.NewCredentials("foo", "bar", map[string]any{
					"client_id":     "baz",
					"client_secret": "foo",
				}), nil)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().SecretsManager().Return(sm)

			endpointCalled = false
			assertRequest = x.IfThenElse(tc.assertRequest != nil,
				tc.assertRequest,
				func(t *testing.T, _ *http.Request) { t.Helper() },
			)
			buildResponse = tc.buildResponse

			tc.configureMocks(t, cch, sm)
			err := cc.init(t.Context(), appCtx)
			require.NoError(t, err)

			req, err := http.NewRequestWithContext(
				ctx,
				http.MethodPost,
				"http//example.com/test?bar=foo",
				nil,
			)
			require.NoError(t, err)

			// WHEN
			err = cc.Apply(req)

			// THEN
			tc.assert(t, err, endpointCalled, req)
		})
	}
}
