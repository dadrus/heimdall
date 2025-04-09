// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
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

package finalizers

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
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/cache"
	mocks2 "github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/rules/oauth2/clientcredentials"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestNewClientCredentialsFinalizer(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		enforceTLS bool
		config     []byte
		assert     func(t *testing.T, err error, finalizer *oauth2ClientCredentialsFinalizer)
	}{
		"without configuration": {
			assert: func(t *testing.T, err error, _ *oauth2ClientCredentialsFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "validation error")
				assert.Contains(t, err.Error(), "token_url")
				assert.Contains(t, err.Error(), "client_id")
				assert.Contains(t, err.Error(), "client_secret")
			},
		},
		"with empty configuration": {
			config: []byte(``),
			assert: func(t *testing.T, err error, _ *oauth2ClientCredentialsFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "validation error")
				assert.Contains(t, err.Error(), "token_url")
				assert.Contains(t, err.Error(), "client_id")
				assert.Contains(t, err.Error(), "client_secret")
			},
		},
		"with unsupported attributes": {
			config: []byte(`
token_url: https://foo.bar
foo: bar
`),
			assert: func(t *testing.T, err error, _ *oauth2ClientCredentialsFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "invalid keys")
			},
		},
		"with bad auth method attributes": {
			config: []byte(`
token_url: https://foo.bar
client_id: foo
client_secret: bar
auth_method: bar
`),
			assert: func(t *testing.T, err error, _ *oauth2ClientCredentialsFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "'auth_method' must be one of [basic_auth request_body]")
			},
		},
		"with minimal valid config with enforced and used TLS": {
			enforceTLS: true,
			config: []byte(`
token_url: https://foo.bar
client_id: foo
client_secret: bar
`),
			assert: func(t *testing.T, err error, finalizer *oauth2ClientCredentialsFinalizer) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, finalizer)

				assert.Equal(t, "fin", finalizer.ID())
				assert.Equal(t, "https://foo.bar", finalizer.cfg.TokenURL)
				assert.Equal(t, "foo", finalizer.cfg.ClientID)
				assert.Equal(t, "bar", finalizer.cfg.ClientSecret)
				assert.Equal(t, clientcredentials.AuthMethodBasicAuth, finalizer.cfg.AuthMethod)
				assert.Nil(t, finalizer.cfg.TTL)
				assert.Empty(t, finalizer.cfg.Scopes)
				assert.False(t, finalizer.ContinueOnError())
				assert.Equal(t, "Authorization", finalizer.headerName)
			},
		},
		"with minimal valid config with enforced but not used TLS": {
			enforceTLS: true,
			config: []byte(`
token_url: http://foo.bar
client_id: foo
client_secret: bar
`),
			assert: func(t *testing.T, err error, _ *oauth2ClientCredentialsFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "'token_url' scheme must be https")
			},
		},
		"with full valid config": {
			config: []byte(`
token_url: https://foo.bar
client_id: foo
client_secret: bar
auth_method: request_body
cache_ttl: 11s
scopes:
  - foo
  - baz
header: 
  name: "X-My-Header"
  scheme: "Bar"
`),
			assert: func(t *testing.T, err error, finalizer *oauth2ClientCredentialsFinalizer) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, finalizer)

				assert.Equal(t, "fin", finalizer.ID())
				assert.Equal(t, "https://foo.bar", finalizer.cfg.TokenURL)
				assert.Equal(t, "foo", finalizer.cfg.ClientID)
				assert.Equal(t, "bar", finalizer.cfg.ClientSecret)
				assert.Equal(t, "X-My-Header", finalizer.headerName)
				assert.Equal(t, "Bar", finalizer.headerScheme)
				assert.Equal(t, clientcredentials.AuthMethodRequestBody, finalizer.cfg.AuthMethod)
				assert.Equal(t, 11*time.Second, *finalizer.cfg.TTL)
				assert.Len(t, finalizer.cfg.Scopes, 2)
				assert.Contains(t, finalizer.cfg.Scopes, "foo")
				assert.Contains(t, finalizer.cfg.Scopes, "baz")
				assert.False(t, finalizer.ContinueOnError())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			es := config.EnforcementSettings{EnforceEgressTLS: tc.enforceTLS}
			validator, err := validation.NewValidator(
				validation.WithTagValidator(es),
				validation.WithErrorTranslator(es),
			)
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Maybe().Return(validator)
			appCtx.EXPECT().Logger().Return(log.Logger)

			// WHEN
			finalizer, err := newOAuth2ClientCredentialsFinalizer(appCtx, "fin", conf)

			// THEN
			tc.assert(t, err, finalizer)
		})
	}
}

func TestCreateClientCredentialsFinalizerFromPrototype(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		prototypeConfig []byte
		config          []byte
		assert          func(t *testing.T, err error, prototype *oauth2ClientCredentialsFinalizer, configured *oauth2ClientCredentialsFinalizer)
	}{
		"no new configuration provided": {
			prototypeConfig: []byte(`
token_url: https://foo.bar
client_id: foo
client_secret: bar
cache_ttl: 11s
scopes:
  - foo
  - baz
header: 
  name: "X-My-Header"
`),
			assert: func(t *testing.T, err error, prototype *oauth2ClientCredentialsFinalizer, configured *oauth2ClientCredentialsFinalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
			},
		},
		"empty configuration provided": {
			prototypeConfig: []byte(`
token_url: https://foo.bar
client_id: foo
client_secret: bar
cache_ttl: 11s
scopes:
  - foo
  - baz
header: 
  name: "X-My-Header"
`),
			config: []byte(``),
			assert: func(t *testing.T, err error, prototype *oauth2ClientCredentialsFinalizer, configured *oauth2ClientCredentialsFinalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
				assert.Equal(t, "fin", configured.ID())
			},
		},
		"scopes reconfigured": {
			prototypeConfig: []byte(`
token_url: https://foo.bar
client_id: foo
client_secret: bar
cache_ttl: 11s
`),
			config: []byte(`
scopes:
  - foo
  - baz
`),
			assert: func(t *testing.T, err error, prototype *oauth2ClientCredentialsFinalizer, configured *oauth2ClientCredentialsFinalizer) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.ID(), configured.ID())
				assert.Equal(t, "https://foo.bar", prototype.cfg.TokenURL)
				assert.Equal(t, prototype.cfg.TokenURL, configured.cfg.TokenURL)
				assert.Equal(t, "foo", prototype.cfg.ClientID)
				assert.Equal(t, prototype.cfg.ClientID, configured.cfg.ClientID)
				assert.Equal(t, "bar", prototype.cfg.ClientSecret)
				assert.Equal(t, prototype.cfg.ClientSecret, configured.cfg.ClientSecret)
				assert.Equal(t, 11*time.Second, *prototype.cfg.TTL)
				assert.Equal(t, prototype.cfg.TTL, configured.cfg.TTL)
				assert.Equal(t, "Authorization", prototype.headerName)
				assert.Equal(t, prototype.headerName, configured.headerName)
				assert.Empty(t, prototype.cfg.Scopes)
				assert.Len(t, configured.cfg.Scopes, 2)
				assert.Contains(t, configured.cfg.Scopes, "foo")
				assert.Contains(t, configured.cfg.Scopes, "baz")
				assert.Equal(t, prototype.cfg.AuthMethod, configured.cfg.AuthMethod)
			},
		},
		"ttl reconfigured": {
			prototypeConfig: []byte(`
token_url: https://foo.bar
client_id: foo
client_secret: bar
cache_ttl: 11s
`),
			config: []byte(`
cache_ttl: 12s
`),
			assert: func(t *testing.T, err error, prototype *oauth2ClientCredentialsFinalizer, configured *oauth2ClientCredentialsFinalizer) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.ID(), configured.ID())
				assert.Equal(t, "https://foo.bar", prototype.cfg.TokenURL)
				assert.Equal(t, prototype.cfg.TokenURL, configured.cfg.TokenURL)
				assert.Equal(t, "foo", prototype.cfg.ClientID)
				assert.Equal(t, prototype.cfg.ClientID, configured.cfg.ClientID)
				assert.Equal(t, "bar", prototype.cfg.ClientSecret)
				assert.Equal(t, prototype.cfg.ClientSecret, configured.cfg.ClientSecret)
				assert.Equal(t, 11*time.Second, *prototype.cfg.TTL)
				assert.Equal(t, 12*time.Second, *configured.cfg.TTL)
				assert.Equal(t, "Authorization", prototype.headerName)
				assert.Equal(t, prototype.headerName, configured.headerName)
				assert.Empty(t, prototype.cfg.Scopes)
				assert.Equal(t, prototype.cfg.Scopes, configured.cfg.Scopes)
				assert.Equal(t, prototype.cfg.AuthMethod, configured.cfg.AuthMethod)
			},
		},
		"unsupported attributes while reconfiguring": {
			prototypeConfig: []byte(`
token_url: https://foo.bar
client_id: foo
client_secret: bar
cache_ttl: 11s
`),
			config: []byte(`
foo: 10s
`),
			assert: func(t *testing.T, err error, prototype *oauth2ClientCredentialsFinalizer, configured *oauth2ClientCredentialsFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed decoding")

				require.NotNil(t, prototype)
				require.Nil(t, configured)
			},
		},
		"header name reconfigured": {
			prototypeConfig: []byte(`
token_url: https://foo.bar
client_id: foo
client_secret: bar
cache_ttl: 11s
`),
			config: []byte(`
header: 
  name: X-Foo-Bar
`),
			assert: func(t *testing.T, err error, prototype *oauth2ClientCredentialsFinalizer, configured *oauth2ClientCredentialsFinalizer) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.ID(), configured.ID())
				assert.Equal(t, "https://foo.bar", prototype.cfg.TokenURL)
				assert.Equal(t, prototype.cfg.TokenURL, configured.cfg.TokenURL)
				assert.Equal(t, "foo", prototype.cfg.ClientID)
				assert.Equal(t, prototype.cfg.ClientID, configured.cfg.ClientID)
				assert.Equal(t, "bar", prototype.cfg.ClientSecret)
				assert.Equal(t, prototype.cfg.ClientSecret, configured.cfg.ClientSecret)
				assert.Equal(t, 11*time.Second, *prototype.cfg.TTL)
				assert.Equal(t, prototype.cfg.TTL, configured.cfg.TTL)
				assert.Equal(t, "Authorization", prototype.headerName)
				assert.Equal(t, "X-Foo-Bar", configured.headerName)
				assert.Empty(t, prototype.cfg.Scopes)
				assert.Equal(t, prototype.cfg.Scopes, configured.cfg.Scopes)
				assert.Equal(t, prototype.cfg.AuthMethod, configured.cfg.AuthMethod)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			pc, err := testsupport.DecodeTestConfig(tc.prototypeConfig)
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			validator, err := validation.NewValidator(
				validation.WithTagValidator(config.EnforcementSettings{}),
			)
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Maybe().Return(validator)
			appCtx.EXPECT().Logger().Return(log.Logger)

			prototype, err := newOAuth2ClientCredentialsFinalizer(appCtx, "fin", pc)
			require.NoError(t, err)

			// WHEN
			finalizer, err := prototype.WithConfig(conf)

			// THEN
			var (
				ok            bool
				realFinalizer *oauth2ClientCredentialsFinalizer
			)

			if err == nil {
				realFinalizer, ok = finalizer.(*oauth2ClientCredentialsFinalizer)
				require.True(t, ok)
			}

			tc.assert(t, err, prototype, realFinalizer)
		})
	}
}

func TestClientCredentialsFinalizerExecute(t *testing.T) {
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
		finalizer      *oauth2ClientCredentialsFinalizer
		configureMocks func(t *testing.T, ctx *mocks.RequestContextMock, cch *mocks2.CacheMock)
		assertRequest  RequestAsserter
		buildResponse  ResponseBuilder
		assert         func(t *testing.T, err error, tokenEndpointCalled bool)
	}{
		"reusing response from cache": {
			finalizer: &oauth2ClientCredentialsFinalizer{
				id:         "test",
				headerName: "Authorization",
			},
			configureMocks: func(t *testing.T, ctx *mocks.RequestContextMock, cch *mocks2.CacheMock) {
				t.Helper()

				rawData, err := json.Marshal(clientcredentials.TokenInfo{AccessToken: "foobar", TokenType: "Bearer"})
				require.NoError(t, err)

				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(rawData, nil)
				ctx.EXPECT().AddHeaderForUpstream("Authorization", "Bearer foobar")
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool) {
				t.Helper()

				require.NoError(t, err)
				assert.False(t, tokenEndpointCalled)
			},
		},
		"error while unmarshalling successful response": {
			finalizer: &oauth2ClientCredentialsFinalizer{
				id: "test",
				cfg: clientcredentials.Config{
					TokenURL:     srv.URL,
					ClientID:     "bar",
					ClientSecret: "foo",
				},
			},
			configureMocks: func(t *testing.T, _ *mocks.RequestContextMock, cch *mocks2.CacheMock) {
				t.Helper()

				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, errors.New("no cache entry"))
			},
			assertRequest: func(t *testing.T, _ *http.Request) { t.Helper() },
			buildResponse: func(t *testing.T) (any, int) {
				t.Helper()

				return "foo", http.StatusOK
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool) {
				t.Helper()

				assert.True(t, tokenEndpointCalled)
				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
			},
		},
		"full configuration, no cache hit and token has expires_in claim": {
			finalizer: &oauth2ClientCredentialsFinalizer{
				id:           "test",
				headerName:   "X-My-Header",
				headerScheme: "Bar",
				cfg: clientcredentials.Config{
					TokenURL:     srv.URL,
					ClientID:     "bar",
					ClientSecret: "foo",
					TTL: func() *time.Duration {
						ttl := 3 * time.Minute

						return &ttl
					}(),
					Scopes: []string{"baz", "zab"},
				},
			},
			configureMocks: func(t *testing.T, ctx *mocks.RequestContextMock, cch *mocks2.CacheMock) {
				t.Helper()

				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, errors.New("no cache entry"))
				cch.EXPECT().Set(mock.Anything, mock.Anything, mock.Anything, 3*time.Minute).Return(nil)
				ctx.EXPECT().AddHeaderForUpstream("X-My-Header", "Bar foobar").Return()
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
					TokenType:   "Foo",
					ExpiresIn:   int64((5 * time.Minute).Seconds()),
				}, http.StatusOK
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, tokenEndpointCalled)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			endpointCalled = false
			configureMocks := x.IfThenElse(tc.configureMocks != nil,
				tc.configureMocks,
				func(t *testing.T, _ *mocks.RequestContextMock, _ *mocks2.CacheMock) { t.Helper() },
			)

			cch := mocks2.NewCacheMock(t)
			ctx := mocks.NewRequestContextMock(t)

			ctx.EXPECT().Context().Return(cache.WithContext(t.Context(), cch))
			configureMocks(t, ctx, cch)

			assertRequest = tc.assertRequest
			buildResponse = tc.buildResponse

			// WHEN
			err := tc.finalizer.Execute(ctx, nil)

			// THEN
			tc.assert(t, err, endpointCalled)
		})
	}
}
