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
	cachemocks "github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/pipeline"
	pipelinemocks "github.com/dadrus/heimdall/internal/pipeline/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/types"
	"github.com/dadrus/heimdall/internal/rules/oauth2/clientcredentials"
	"github.com/dadrus/heimdall/internal/secrets"
	secretsmocks "github.com/dadrus/heimdall/internal/secrets/mocks"
	secrettypes "github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestNewOAuth2ClientCredentialsFinalizer(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		enforceTLS bool
		config     []byte
		setup      func(t *testing.T, resolver *secretsmocks.ResolverMock)
		assert     func(t *testing.T, err error, finalizer *oauth2ClientCredentialsFinalizer)
	}{
		"without configuration": {
			assert: func(t *testing.T, err error, _ *oauth2ClientCredentialsFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "validation error")
				require.ErrorContains(t, err, "token_url")
				require.ErrorContains(t, err, "credentials")
			},
		},
		"with unsupported attributes": {
			config: []byte(`
credentials:
  source: foo
  selector: bar
token_url: https://foo.bar
foo: bar
`),
			setup: func(t *testing.T, resolver *secretsmocks.ResolverMock) {
				t.Helper()

				ch := secretsmocks.NewCredentialsHandleMock(t)

				resolver.EXPECT().Credentials(mock.Anything).Return(ch, nil)

				ch.EXPECT().OnUpdate(mock.Anything)
			},
			assert: func(t *testing.T, err error, finalizer *oauth2ClientCredentialsFinalizer) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, finalizer)
				require.NotNil(t, finalizer.informer)
			},
		},
		"with bad auth method attributes": {
			config: []byte(`
token_url: https://foo.bar
credentials:
  source: foo
  selector: bar
auth_method: bar
`),
			assert: func(t *testing.T, err error, _ *oauth2ClientCredentialsFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "'auth_method' must be one of [basic_auth request_body]")
			},
		},
		"with minimal valid config with enforced and used TLS": {
			enforceTLS: true,
			config: []byte(`
token_url: https://foo.bar
credentials:
  source: foo
  selector: bar
`),
			setup: func(t *testing.T, resolver *secretsmocks.ResolverMock) {
				t.Helper()

				ch := secretsmocks.NewCredentialsHandleMock(t)

				resolver.EXPECT().Credentials(mock.Anything).Return(ch, nil)

				ch.EXPECT().OnUpdate(mock.Anything)
			},
			assert: func(t *testing.T, err error, finalizer *oauth2ClientCredentialsFinalizer) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, finalizer)
				require.NotNil(t, finalizer.informer)

				assert.Equal(t, "with minimal valid config with enforced and used TLS", finalizer.ID())
				assert.Equal(t, finalizer.Name(), finalizer.ID())
				assert.Equal(t, types.KindFinalizer, finalizer.Kind())
				assert.Equal(t, finalizer.ID(), finalizer.Type())
				assert.Equal(t, "https://foo.bar", finalizer.cfg.TokenURL)
				assert.Equal(t, clientcredentials.AuthMethodBasicAuth, finalizer.cfg.AuthMethod)
				assert.Nil(t, finalizer.cfg.TTL)
				assert.Empty(t, finalizer.cfg.Scopes)
				assert.Equal(t, "Authorization", finalizer.headerName)
				assert.Empty(t, finalizer.headerScheme)
			},
		},
		"with minimal valid config with enforced but not used TLS": {
			enforceTLS: true,
			config: []byte(`
token_url: http://foo.bar
credentials:
  source: foo
  selector: bar
`),
			assert: func(t *testing.T, err error, _ *oauth2ClientCredentialsFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "'token_url' scheme must be https")
			},
		},
		"with full valid config": {
			config: []byte(`
token_url: https://foo.bar
credentials:
  source: foo
  selector: bar
auth_method: request_body
cache_ttl: 11s
scopes:
  - foo
  - baz
header: 
  name: "X-My-Header"
  scheme: "Bar"
`),
			setup: func(t *testing.T, resolver *secretsmocks.ResolverMock) {
				t.Helper()

				ch := secretsmocks.NewCredentialsHandleMock(t)

				resolver.EXPECT().Credentials(mock.Anything).Return(ch, nil)

				ch.EXPECT().OnUpdate(mock.Anything)
			},
			assert: func(t *testing.T, err error, finalizer *oauth2ClientCredentialsFinalizer) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, finalizer)
				require.NotNil(t, finalizer.informer)

				assert.Equal(t, "with full valid config", finalizer.ID())
				assert.Equal(t, finalizer.Name(), finalizer.ID())
				assert.Equal(t, types.KindFinalizer, finalizer.Kind())
				assert.Equal(t, finalizer.ID(), finalizer.Type())
				assert.Equal(t, "https://foo.bar", finalizer.cfg.TokenURL)
				assert.Equal(t, "X-My-Header", finalizer.headerName)
				assert.Equal(t, "Bar", finalizer.headerScheme)
				assert.Equal(t, clientcredentials.AuthMethodRequestBody, finalizer.cfg.AuthMethod)
				assert.Equal(t, 11*time.Second, *finalizer.cfg.TTL)
				assert.Len(t, finalizer.cfg.Scopes, 2)
				assert.Contains(t, finalizer.cfg.Scopes, "foo")
				assert.Contains(t, finalizer.cfg.Scopes, "baz")
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

			setupResolver := x.IfThenElse(
				tc.setup != nil,
				tc.setup,
				func(t *testing.T, _ *secretsmocks.ResolverMock) { t.Helper() },
			)
			resolver := secretsmocks.NewResolverMock(t)
			setupResolver(t, resolver)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().DecoderFactory().Maybe().
				Return(encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct)))
			appCtx.EXPECT().Logger().Return(log.Logger)
			appCtx.EXPECT().SecretResolver().Maybe().Return(resolver)

			// WHEN
			mech, err := newOAuth2ClientCredentialsFinalizer(appCtx, uc, conf)

			// THEN
			fin, ok := mech.(*oauth2ClientCredentialsFinalizer)
			if err == nil {
				require.True(t, ok)
			}

			tc.assert(t, err, fin)
		})
	}
}

func TestOAuth2ClientCredentialsFinalizerCreateStep(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		prototypeConfig []byte
		stepDef         types.StepDefinition
		assert          func(t *testing.T, err error, prototype, configured *oauth2ClientCredentialsFinalizer)
	}{
		"no new configuration and no step ID": {
			prototypeConfig: []byte(`
token_url: https://foo.bar
credentials:
  source: foo
  selector: bar
cache_ttl: 11s
scopes:
  - foo
  - baz
header: 
  name: "X-My-Header"
`),
			assert: func(t *testing.T, err error, prototype, configured *oauth2ClientCredentialsFinalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
			},
		},
		"no new configuration but with step ID": {
			prototypeConfig: []byte(`
token_url: https://foo.bar
credentials:
  source: foo
  selector: bar
cache_ttl: 11s
scopes:
  - foo
  - baz
header: 
  name: "X-My-Header"
`),
			stepDef: types.StepDefinition{ID: "foo"},
			assert: func(t *testing.T, err error, prototype, configured *oauth2ClientCredentialsFinalizer) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, "foo", configured.ID())
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, prototype.Name(), prototype.ID())
				assert.Equal(t, types.KindFinalizer, configured.Kind())
				assert.Equal(t, prototype.Type(), configured.Type())
				assert.Equal(t, prototype.cfg, configured.cfg)
				assert.Equal(t, prototype.app, configured.app)
				assert.Equal(t, prototype.informer, configured.informer)
				assert.Equal(t, prototype.headerName, configured.headerName)
				assert.Equal(t, prototype.headerScheme, configured.headerScheme)
			},
		},
		"scopes reconfigured and step ID set": {
			prototypeConfig: []byte(`
token_url: https://foo.bar
credentials:
  source: foo
  selector: bar
cache_ttl: 11s
`),
			stepDef: types.StepDefinition{
				ID:     "foo",
				Config: config.MechanismConfig{"scopes": []string{"foo", "baz"}},
			},
			assert: func(t *testing.T, err error, prototype, configured *oauth2ClientCredentialsFinalizer) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.NotEqual(t, prototype.ID(), configured.ID())
				assert.Equal(t, "foo", configured.ID())
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, types.KindFinalizer, configured.Kind())
				assert.Equal(t, prototype.Type(), configured.Type())
				assert.Equal(t, "https://foo.bar", prototype.cfg.TokenURL)
				assert.Equal(t, prototype.cfg.TokenURL, configured.cfg.TokenURL)
				assert.Equal(t, 11*time.Second, *prototype.cfg.TTL)
				assert.Equal(t, prototype.cfg.TTL, configured.cfg.TTL)
				assert.Equal(t, "Authorization", prototype.headerName)
				assert.Equal(t, prototype.headerName, configured.headerName)
				assert.Empty(t, prototype.cfg.Scopes)
				assert.Len(t, configured.cfg.Scopes, 2)
				assert.Contains(t, configured.cfg.Scopes, "foo")
				assert.Contains(t, configured.cfg.Scopes, "baz")
				assert.Equal(t, prototype.cfg.AuthMethod, configured.cfg.AuthMethod)
				assert.Equal(t, prototype.informer, configured.informer)
			},
		},
		"ttl reconfigured": {
			prototypeConfig: []byte(`
token_url: https://foo.bar
credentials:
  source: foo
  selector: bar
cache_ttl: 11s
`),
			stepDef: types.StepDefinition{
				Config: config.MechanismConfig{"cache_ttl": "12s"},
			},
			assert: func(t *testing.T, err error, prototype, configured *oauth2ClientCredentialsFinalizer) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.ID(), configured.ID())
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, types.KindFinalizer, configured.Kind())
				assert.Equal(t, prototype.Type(), configured.Type())
				assert.Equal(t, "https://foo.bar", prototype.cfg.TokenURL)
				assert.Equal(t, prototype.cfg.TokenURL, configured.cfg.TokenURL)
				assert.Equal(t, 11*time.Second, *prototype.cfg.TTL)
				assert.Equal(t, 12*time.Second, *configured.cfg.TTL)
				assert.Equal(t, "Authorization", prototype.headerName)
				assert.Equal(t, prototype.headerName, configured.headerName)
				assert.Empty(t, prototype.cfg.Scopes)
				assert.Equal(t, prototype.cfg.Scopes, configured.cfg.Scopes)
				assert.Equal(t, prototype.cfg.AuthMethod, configured.cfg.AuthMethod)
				assert.Equal(t, prototype.informer, configured.informer)
			},
		},
		"unsupported attributes while reconfiguring": {
			prototypeConfig: []byte(`
token_url: https://foo.bar
credentials:
  source: foo
  selector: bar
cache_ttl: 11s
`),
			stepDef: types.StepDefinition{
				Config: config.MechanismConfig{"foo": "1s"},
			},
			assert: func(t *testing.T, err error, prototype, configured *oauth2ClientCredentialsFinalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
			},
		},
		"malformed step configuration": {
			prototypeConfig: []byte(`
token_url: https://foo.bar
credentials:
  source: foo
  selector: bar
cache_ttl: 11s
`),
			stepDef: types.StepDefinition{
				Config: config.MechanismConfig{"token_url": 1},
			},
			assert: func(t *testing.T, err error, _, _ *oauth2ClientCredentialsFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed decoding")
			},
		},
		"header name reconfigured": {
			prototypeConfig: []byte(`
token_url: https://foo.bar
credentials:
  source: foo
  selector: bar
cache_ttl: 11s
`),
			stepDef: types.StepDefinition{
				Config: config.MechanismConfig{"header": map[string]any{"name": "X-Foo-Bar"}},
			},
			assert: func(t *testing.T, err error, prototype, configured *oauth2ClientCredentialsFinalizer) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.ID(), configured.ID())
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, types.KindFinalizer, configured.Kind())
				assert.Equal(t, "https://foo.bar", prototype.cfg.TokenURL)
				assert.Equal(t, prototype.Type(), configured.Type())
				assert.Equal(t, prototype.cfg.TokenURL, configured.cfg.TokenURL)
				assert.Equal(t, 11*time.Second, *prototype.cfg.TTL)
				assert.Equal(t, prototype.cfg.TTL, configured.cfg.TTL)
				assert.Equal(t, "Authorization", prototype.headerName)
				assert.Equal(t, "X-Foo-Bar", configured.headerName)
				assert.Empty(t, prototype.cfg.Scopes)
				assert.Equal(t, prototype.cfg.Scopes, configured.cfg.Scopes)
				assert.Equal(t, prototype.cfg.AuthMethod, configured.cfg.AuthMethod)
				assert.Equal(t, prototype.informer, configured.informer)
			},
		},
		"header name and scheme reconfigured": {
			prototypeConfig: []byte(`
token_url: https://foo.bar
credentials:
  source: foo
  selector: bar
cache_ttl: 11s
header:
  name: "X-Original-Header"
  scheme: "Original"
`),
			stepDef: types.StepDefinition{
				Config: config.MechanismConfig{
					"header": map[string]any{"name": "X-Foo-Bar", "scheme": "Foo"},
				},
			},
			assert: func(t *testing.T, err error, prototype, configured *oauth2ClientCredentialsFinalizer) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, "X-Original-Header", prototype.headerName)
				assert.Equal(t, "Original", prototype.headerScheme)
				assert.Equal(t, "X-Foo-Bar", configured.headerName)
				assert.Equal(t, "Foo", configured.headerScheme)
				assert.Equal(t, prototype.cfg, configured.cfg)
				assert.Equal(t, prototype.informer, configured.informer)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			pc, err := testsupport.DecodeTestConfig(tc.prototypeConfig)
			require.NoError(t, err)

			validator, err := validation.NewValidator(
				validation.WithTagValidator(config.EnforcementSettings{}),
			)
			require.NoError(t, err)

			ch := secretsmocks.NewCredentialsHandleMock(t)
			ch.EXPECT().OnUpdate(mock.Anything)

			resolver := secretsmocks.NewResolverMock(t)
			resolver.EXPECT().Credentials(mock.Anything).Return(ch, nil)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().DecoderFactory().Maybe().
				Return(encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct)))
			appCtx.EXPECT().Logger().Return(log.Logger)
			appCtx.EXPECT().SecretResolver().Maybe().Return(resolver)

			mech, err := newOAuth2ClientCredentialsFinalizer(appCtx, uc, pc)
			require.NoError(t, err)

			configured, ok := mech.(*oauth2ClientCredentialsFinalizer)
			require.True(t, ok)

			// WHEN
			step, err := mech.CreateStep(resolver, tc.stepDef)

			// THEN
			fin, ok := step.(*oauth2ClientCredentialsFinalizer)
			if err == nil {
				require.True(t, ok)
			}

			tc.assert(t, err, configured, fin)
		})
	}
}

func TestOAuth2ClientCredentialsFinalizerExecute(t *testing.T) {
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
		config         []byte
		configureMocks func(t *testing.T, ctx *pipelinemocks.ContextMock, cch *cachemocks.CacheMock, rm *secretsmocks.ResolverMock)
		assertRequest  RequestAsserter
		buildResponse  ResponseBuilder
		assert         func(t *testing.T, err error, tokenEndpointCalled bool)
	}{
		"credentials are not available": {
			config: []byte(`
credentials:
  source: foo
  selector: bar
token_url: ` + srv.URL + `
`),
			configureMocks: func(t *testing.T, _ *pipelinemocks.ContextMock, _ *cachemocks.CacheMock, rm *secretsmocks.ResolverMock) {
				t.Helper()

				ch := secretsmocks.NewCredentialsHandleMock(t)

				rm.EXPECT().
					Credentials(secrets.Reference{Source: "foo", Selector: "bar"}).
					Return(ch, nil)

				ch.EXPECT().OnUpdate(mock.Anything)
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "oauth2 client credentials are not available")
				assert.False(t, tokenEndpointCalled)
			},
		},
		"credentials decoding fails": {
			config: []byte(`
credentials:
  source: foo
  selector: bar
token_url: ` + srv.URL + `
`),
			configureMocks: func(t *testing.T, _ *pipelinemocks.ContextMock, _ *cachemocks.CacheMock, rm *secretsmocks.ResolverMock) {
				t.Helper()

				chm := secretsmocks.NewCredentialsHandleMock(t)

				rm.EXPECT().
					Credentials(secrets.Reference{Source: "foo", Selector: "bar"}).
					Return(chm, nil)

				chm.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Credentials]) bool {
						err := cb(t.Context(), secrettypes.NewCredentials("bar", map[string]any{
							"client-id":     "foo",
							"client_secret": "bar",
						}))
						require.Error(t, err)

						return true
					}))
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "oauth2 client credentials are not available")
				assert.False(t, tokenEndpointCalled)
			},
		},
		"reusing response from cache": {
			config: []byte(`
credentials:
  source: foo
  selector: bar
token_url: ` + srv.URL + `
`),
			configureMocks: func(t *testing.T, ctx *pipelinemocks.ContextMock, cch *cachemocks.CacheMock, rm *secretsmocks.ResolverMock) {
				t.Helper()

				credentials := secrettypes.NewCredentials("bar", map[string]any{
					"client_id":     "foo",
					"client_secret": "bar",
				})

				chm := secretsmocks.NewCredentialsHandleMock(t)

				rm.EXPECT().Credentials(mock.Anything).Return(chm, nil)

				chm.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Credentials]) bool {
						err := cb(t.Context(), credentials)
						require.NoError(t, err)

						return true
					}))

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
			config: []byte(`
credentials:
  source: foo
  selector: bar
token_url: ` + srv.URL + `
`),
			configureMocks: func(t *testing.T, _ *pipelinemocks.ContextMock, cch *cachemocks.CacheMock, rm *secretsmocks.ResolverMock) {
				t.Helper()

				credentials := secrettypes.NewCredentials("bar", map[string]any{
					"client_id":     "foo",
					"client_secret": "bar",
				})

				chm := secretsmocks.NewCredentialsHandleMock(t)

				rm.EXPECT().Credentials(secrets.Reference{Source: "foo", Selector: "bar"}).
					Return(chm, nil)

				chm.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Credentials]) bool {
						err := cb(t.Context(), credentials)
						require.NoError(t, err)

						return true
					}))

				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, assert.AnError)
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
				require.ErrorIs(t, err, pipeline.ErrInternal)
			},
		},
		"full configuration, no cache hit and token has expires_in claim": {
			config: []byte(`
credentials:
  source: foo
  selector: bar
token_url: ` + srv.URL + `
header:
  name: "X-My-Header"
  scheme: "Bar"
scopes: ["baz", "zab"]
cache_ttl: 3m
`),
			configureMocks: func(t *testing.T, ctx *pipelinemocks.ContextMock, cch *cachemocks.CacheMock, rm *secretsmocks.ResolverMock) {
				t.Helper()

				credentials := secrettypes.NewCredentials("bar", map[string]any{
					"client_id":     "bar",
					"client_secret": "baz",
				})

				chm := secretsmocks.NewCredentialsHandleMock(t)

				rm.EXPECT().Credentials(mock.Anything).Return(chm, nil)

				chm.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Credentials]) bool {
						err := cb(t.Context(), credentials)
						require.NoError(t, err)

						return true
					}))

				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, assert.AnError)
				cch.EXPECT().Set(mock.Anything, mock.Anything, mock.Anything, 3*time.Minute).Return(nil)
				ctx.EXPECT().AddHeaderForUpstream("X-My-Header", "Bar foobar").Return()
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				val, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(req.Header.Get("Authorization"), "Basic "))
				require.NoError(t, err)

				clientIDAndSecret := strings.Split(string(val), ":")
				require.Len(t, clientIDAndSecret, 2)
				assert.Equal(t, "bar", clientIDAndSecret[0])
				assert.Equal(t, "baz", clientIDAndSecret[1])

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
			// GIVEN
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			validator, err := validation.NewValidator(
				validation.WithTagValidator(config.EnforcementSettings{}),
			)
			require.NoError(t, err)

			resolver := secretsmocks.NewResolverMock(t)
			cch := cachemocks.NewCacheMock(t)
			ctx := pipelinemocks.NewContextMock(t)
			ctx.EXPECT().Context().Return(cache.WithContext(t.Context(), cch))

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().DecoderFactory().Maybe().
				Return(encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct)))
			appCtx.EXPECT().Logger().Return(log.Logger)
			appCtx.EXPECT().SecretResolver().Return(resolver)

			tc.configureMocks(t, ctx, cch, resolver)

			mech, err := newOAuth2ClientCredentialsFinalizer(appCtx, uc, conf)
			require.NoError(t, err)

			step, err := mech.CreateStep(resolver, types.StepDefinition{ID: "test"})
			require.NoError(t, err)

			endpointCalled = false

			assertRequest = x.IfThenElse(
				tc.assertRequest != nil,
				tc.assertRequest,
				func(t *testing.T, _ *http.Request) { t.Helper() },
			)
			buildResponse = x.IfThenElse(
				tc.buildResponse != nil,
				tc.buildResponse,
				func(t *testing.T) (any, int) {
					t.Helper()

					return &Token{AccessToken: "foobar", TokenType: "Bearer"}, http.StatusOK
				},
			)

			// WHEN
			err = step.Execute(ctx, nil)

			// THEN
			tc.assert(t, err, endpointCalled)
		})
	}
}

func TestOAuth2ClientCredentialsFinalizerAccept(t *testing.T) {
	t.Parallel()

	mech := &oauth2ClientCredentialsFinalizer{}

	mech.Accept(nil)
}
