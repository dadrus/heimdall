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
	cachemocks "github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/oauth2/clientcredentials"
	"github.com/dadrus/heimdall/internal/secrets"
	secretsmocks "github.com/dadrus/heimdall/internal/secrets/mocks"
	"github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/x"
)

func TestOAuth2ClientCredentialsInit(t *testing.T) {
	t.Parallel()

	ttl := time.Minute

	for uc, tc := range map[string]struct {
		header *headerConfig
		setup  func(t *testing.T, sr *secretsmocks.ResolverMock, handle *secretsmocks.CredentialsHandleMock)
		assert func(t *testing.T, err error, cc *OAuth2ClientCredentials)
	}{
		"fails to resolve credentials": {
			setup: func(t *testing.T, sr *secretsmocks.ResolverMock, _ *secretsmocks.CredentialsHandleMock) {
				t.Helper()

				sr.EXPECT().
					Credentials(secrets.Reference{Source: "foo", Selector: "bar"}).
					Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, err error, cc *OAuth2ClientCredentials) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "failed resolving oauth2 client credentials")

				assert.Nil(t, cc.Hash())
				assert.Nil(t, cc.informer)
			},
		},
		"succeeds without custom header": {
			setup: func(t *testing.T, sr *secretsmocks.ResolverMock, handle *secretsmocks.CredentialsHandleMock) {
				t.Helper()

				creds := types.NewCredentials("bar", map[string]any{
					"client_id":     "baz",
					"client_secret": "foo",
				})

				sr.EXPECT().
					Credentials(secrets.Reference{Source: "foo", Selector: "bar"}).
					Return(handle, nil)

				handle.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Credentials]) bool {
						err := cb(t.Context(), creds)
						require.NoError(t, err)

						return true
					}))
			},
			assert: func(t *testing.T, err error, cc *OAuth2ClientCredentials) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, cc.Header)
				assert.Equal(t, "Authorization", cc.Header.Name)
				assert.Equal(t, "Bearer", cc.Header.Scheme)
				require.NotNil(t, cc.informer)

				exp := clientcredentials.Config{
					TokenURL:     "https://example.com/token",
					ClientID:     "baz",
					ClientSecret: "foo",
					AuthMethod:   clientcredentials.AuthMethodBasicAuth,
					Scopes:       []string{"foo", "bar"},
					TTL:          &ttl,
				}

				val, ok := cc.informer.Get()
				require.True(t, ok)
				assert.Equal(t, exp, val)
				assert.NotEmpty(t, cc.Hash())
			},
		},
		"succeeds with custom header": {
			header: &headerConfig{Name: "X-My-Header", Scheme: "Foo"},
			setup: func(t *testing.T, sr *secretsmocks.ResolverMock, handle *secretsmocks.CredentialsHandleMock) {
				t.Helper()

				creds := types.NewCredentials("bar", map[string]any{
					"client_id":     "baz",
					"client_secret": "foo",
				})

				sr.EXPECT().
					Credentials(secrets.Reference{Source: "foo", Selector: "bar"}).
					Return(handle, nil)

				handle.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Credentials]) bool {
						err := cb(t.Context(), creds)
						require.NoError(t, err)

						return true
					}))
			},
			assert: func(t *testing.T, err error, cc *OAuth2ClientCredentials) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, cc.Header)
				assert.Equal(t, "X-My-Header", cc.Header.Name)
				assert.Equal(t, "Foo", cc.Header.Scheme)
				require.NotNil(t, cc.informer)

				exp := clientcredentials.Config{
					TokenURL:     "https://example.com/token",
					ClientID:     "baz",
					ClientSecret: "foo",
					AuthMethod:   clientcredentials.AuthMethodBasicAuth,
					Scopes:       []string{"foo", "bar"},
					TTL:          &ttl,
				}

				val, ok := cc.informer.Get()
				require.True(t, ok)
				assert.Equal(t, exp, val)
				assert.NotEmpty(t, cc.Hash())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			secret := config.Secret{Source: "foo", Selector: "bar"}

			sr := secretsmocks.NewResolverMock(t)
			handle := secretsmocks.NewCredentialsHandleMock(t)
			validator, err := validation.NewValidator(
				validation.WithTagValidator(config.EnforcementSettings{}),
			)
			require.NoError(t, err)

			tc.setup(t, sr, handle)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().SecretResolver().Return(sr)
			appCtx.EXPECT().DecoderFactory().Maybe().
				Return(encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct)))

			cc := &OAuth2ClientCredentials{
				TokenURL:    "https://example.com/token",
				Credentials: secret,
				AuthMethod:  clientcredentials.AuthMethodBasicAuth,
				Scopes:      []string{"foo", "bar"},
				Header:      tc.header,
				TTL:         &ttl,
			}

			err = cc.init(appCtx)

			tc.assert(t, err, cc)
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

	for uc, tc := range map[string]struct {
		header         *headerConfig
		ttl            *time.Duration
		configureMocks func(
			t *testing.T,
			cch *cachemocks.CacheMock,
			sr *secretsmocks.ResolverMock,
			handle *secretsmocks.CredentialsHandleMock,
		)
		assertRequest RequestAsserter
		buildResponse ResponseBuilder
		assert        func(t *testing.T, err error, tokenEndpointCalled bool, req *http.Request)
	}{
		"no credentials available": {
			configureMocks: func(
				t *testing.T,
				_ *cachemocks.CacheMock,
				sr *secretsmocks.ResolverMock,
				handle *secretsmocks.CredentialsHandleMock,
			) {
				t.Helper()

				sr.EXPECT().
					Credentials(secrets.Reference{Source: "foo", Selector: "bar"}).
					Return(handle, nil)

				handle.EXPECT().OnUpdate(mock.Anything)
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool, req *http.Request) {
				t.Helper()

				assert.False(t, tokenEndpointCalled)
				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrInternal)
				require.ErrorContains(t, err, "oauth2 client credentials are not available")
				assert.Empty(t, req.Header)
			},
		},
		"invalid credentials structure": {
			configureMocks: func(
				t *testing.T,
				_ *cachemocks.CacheMock,
				sr *secretsmocks.ResolverMock,
				handle *secretsmocks.CredentialsHandleMock,
			) {
				t.Helper()

				creds := types.NewCredentials("bar", map[string]any{
					"foo": "baz",
					"bar": "foo",
				})

				sr.EXPECT().
					Credentials(secrets.Reference{Source: "foo", Selector: "bar"}).
					Return(handle, nil)

				handle.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Credentials]) bool {
						err := cb(t.Context(), creds)
						require.Error(t, err)
						require.ErrorIs(t, err, pipeline.ErrConfiguration)
						require.ErrorContains(t, err, "failed decoding oauth2 client credentials")

						return true
					}))
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool, req *http.Request) {
				t.Helper()

				assert.False(t, tokenEndpointCalled)
				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrInternal)
				require.ErrorContains(t, err, "oauth2 client credentials are not available")
				assert.Empty(t, req.Header)
			},
		},
		"reusing response from cache, no custom header": {
			configureMocks: func(
				t *testing.T,
				cch *cachemocks.CacheMock,
				sr *secretsmocks.ResolverMock,
				handle *secretsmocks.CredentialsHandleMock,
			) {
				t.Helper()

				rawData, err := json.Marshal(clientcredentials.TokenInfo{
					AccessToken: "foobar",
					TokenType:   "Bearer",
				})
				require.NoError(t, err)

				creds := types.NewCredentials("bar", map[string]any{
					"client_id":     "baz",
					"client_secret": "foo",
				})

				sr.EXPECT().
					Credentials(secrets.Reference{Source: "foo", Selector: "bar"}).
					Return(handle, nil)

				handle.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Credentials]) bool {
						err := cb(t.Context(), creds)
						require.NoError(t, err)

						return true
					}))

				cch.EXPECT().
					Get(mock.Anything, mock.Anything).
					Return(rawData, nil)
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool, req *http.Request) {
				t.Helper()

				require.NoError(t, err)
				assert.False(t, tokenEndpointCalled)
				assert.Equal(t, "Bearer foobar", req.Header.Get("Authorization"))
			},
		},
		"error while unmarshalling successful response": {
			configureMocks: func(
				t *testing.T,
				cch *cachemocks.CacheMock,
				sr *secretsmocks.ResolverMock,
				handle *secretsmocks.CredentialsHandleMock,
			) {
				t.Helper()

				creds := types.NewCredentials("bar", map[string]any{
					"client_id":     "baz",
					"client_secret": "foo",
				})

				sr.EXPECT().
					Credentials(secrets.Reference{Source: "foo", Selector: "bar"}).
					Return(handle, nil)

				handle.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Credentials]) bool {
						err := cb(t.Context(), creds)
						require.NoError(t, err)

						return true
					}))

				cch.EXPECT().
					Get(mock.Anything, mock.Anything).
					Return(nil, assert.AnError)
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
			configureMocks: func(
				t *testing.T,
				cch *cachemocks.CacheMock,
				sr *secretsmocks.ResolverMock,
				handle *secretsmocks.CredentialsHandleMock,
			) {
				t.Helper()

				creds := types.NewCredentials("bar", map[string]any{
					"client_id":     "baz",
					"client_secret": "foo",
				})

				sr.EXPECT().
					Credentials(secrets.Reference{Source: "foo", Selector: "bar"}).
					Return(handle, nil)

				handle.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Credentials]) bool {
						err := cb(t.Context(), creds)
						require.NoError(t, err)

						return true
					}))

				cch.EXPECT().
					Get(mock.Anything, mock.Anything).
					Return(nil, assert.AnError)

				cch.EXPECT().
					Set(mock.Anything, mock.Anything, mock.Anything, 3*time.Minute).
					Return(nil)
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
			t.Parallel()

			endpointCalled := false

			assertRequest := x.IfThenElse(tc.assertRequest != nil,
				tc.assertRequest,
				func(t *testing.T, _ *http.Request) { t.Helper() },
			)

			buildResponse := x.IfThenElse(tc.buildResponse != nil,
				tc.buildResponse,
				func(t *testing.T) (any, int) {
					t.Helper()

					return map[string]any{
						"access_token": "foobar",
						"token_type":   "Bearer",
					}, http.StatusOK
				},
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
			t.Cleanup(srv.Close)

			validator, err := validation.NewValidator(
				validation.WithTagValidator(config.EnforcementSettings{}),
			)
			require.NoError(t, err)

			cc := &OAuth2ClientCredentials{
				TokenURL:    srv.URL,
				Credentials: config.Secret{Source: "foo", Selector: "bar"},
				AuthMethod:  clientcredentials.AuthMethodBasicAuth,
				Scopes:      []string{"baz", "zab"},
				TTL:         tc.ttl,
				Header:      tc.header,
			}

			cch := cachemocks.NewCacheMock(t)
			ctx := cache.WithContext(t.Context(), cch)

			sr := secretsmocks.NewResolverMock(t)
			handle := secretsmocks.NewCredentialsHandleMock(t)

			tc.configureMocks(t, cch, sr, handle)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().SecretResolver().Return(sr)
			appCtx.EXPECT().DecoderFactory().Maybe().
				Return(encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct)))

			err = cc.init(appCtx)
			require.NoError(t, err)

			req, err := http.NewRequestWithContext(
				ctx,
				http.MethodPost,
				"http://example.com/test?bar=foo",
				nil,
			)
			require.NoError(t, err)

			err = cc.Apply(req)

			tc.assert(t, err, endpointCalled, req)
		})
	}
}

func TestOAuth2ClientCredentialsCreateClientCredentialsConfig(t *testing.T) {
	t.Parallel()

	ttl := time.Minute

	for uc, tc := range map[string]struct {
		credentials secrets.Credentials
		assert      func(t *testing.T, got clientcredentials.Config, err error)
	}{
		"creates config": {
			credentials: types.NewCredentials("bar", map[string]any{
				"client_id":     "baz",
				"client_secret": "foo",
			}),
			assert: func(t *testing.T, got clientcredentials.Config, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "https://example.com/token", got.TokenURL)
				assert.Equal(t, "baz", got.ClientID)
				assert.Equal(t, "foo", got.ClientSecret)
				assert.Equal(t, clientcredentials.AuthMethodBasicAuth, got.AuthMethod)
				assert.Equal(t, []string{"foo", "bar"}, got.Scopes)
				assert.Same(t, &ttl, got.TTL)
			},
		},
		"returns decode error": {
			credentials: types.NewCredentials("bar", map[string]any{
				"foo": "baz",
				"bar": "foo",
			}),
			assert: func(t *testing.T, got clientcredentials.Config, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed decoding oauth2 client credentials")
				assert.Empty(t, got)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			validator, err := validation.NewValidator(
				validation.WithTagValidator(config.EnforcementSettings{}),
			)
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().DecoderFactory().Maybe().
				Return(encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct)))

			cc := &OAuth2ClientCredentials{
				TokenURL:   "https://example.com/token",
				AuthMethod: clientcredentials.AuthMethodBasicAuth,
				Scopes:     []string{"foo", "bar"},
				TTL:        &ttl,
				appCtx:     appCtx,
			}

			got, err := cc.createClientCredentialsConfig(tc.credentials)

			tc.assert(t, got, err)
		})
	}
}
