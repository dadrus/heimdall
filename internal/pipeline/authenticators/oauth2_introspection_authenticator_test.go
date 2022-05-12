package authenticators

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/authenticators/extractors"
	"github.com/dadrus/heimdall/internal/pipeline/endpoint"
	"github.com/dadrus/heimdall/internal/pipeline/oauth2"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/pipeline/testsupport"
	"github.com/dadrus/heimdall/internal/x"
)

func TestCreateOAuth2IntrospectionAuthenticator(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		uc     string
		config []byte
		assert func(t *testing.T, err error, a *oauth2IntrospectionAuthenticator)
	}{
		{
			uc: "with unsupported fields",
			config: []byte(`
assertions:
  issuers:
    - foobar
session:
  subject_id_from: some_template
foo: bar
`),
			assert: func(t *testing.T, err error, _ *oauth2IntrospectionAuthenticator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to unmarshal")
			},
		},
		{
			uc: "with missing introspection url config",
			config: []byte(`
assertions:
  issuers:
    - foobar
session:
  subject_id_from: some_template
`),
			assert: func(t *testing.T, err error, _ *oauth2IntrospectionAuthenticator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "validate endpoint")
			},
		},
		{
			uc: "with missing trusted issuers assertion config",
			config: []byte(`
introspection_endpoint:
  url: foobar.local
session:
  subject_id_from: some_template
`),
			assert: func(t *testing.T, err error, _ *oauth2IntrospectionAuthenticator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no trusted issuers")
			},
		},
		{
			uc: "with missing session config",
			config: []byte(`
introspection_endpoint:
  url: foobar.local
assertions:
  issuers:
    - foobar
`),
			assert: func(t *testing.T, err error, auth *oauth2IntrospectionAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				assert.IsType(t, &Session{}, auth.sf)
				sess, ok := auth.sf.(*Session)
				assert.True(t, ok)
				assert.Equal(t, "sub", sess.SubjectIDFrom)
			},
		},
		{
			uc: "with valid config with defaults",
			config: []byte(`
introspection_endpoint:
  url: foobar.local
assertions:
  issuers:
    - foobar
session:
  subject_id_from: some_template
`),
			assert: func(t *testing.T, err error, auth *oauth2IntrospectionAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				// assert endpoint config
				assert.Equal(t, "foobar.local", auth.e.URL)
				assert.Equal(t, http.MethodPost, auth.e.Method)
				assert.Len(t, auth.e.Headers, 2)
				assert.Contains(t, auth.e.Headers, "Content-Type")
				assert.Equal(t, auth.e.Headers["Content-Type"], "application/x-www-form-urlencoded")
				assert.Contains(t, auth.e.Headers, "Accept")
				assert.Equal(t, auth.e.Headers["Accept"], "application/json")
				assert.Nil(t, auth.e.AuthStrategy)
				assert.Nil(t, auth.e.Retry)

				// assert assertions
				assert.Len(t, auth.a.AllowedAlgorithms, len(defaultAllowedAlgorithms()))
				assert.ElementsMatch(t, auth.a.AllowedAlgorithms, defaultAllowedAlgorithms())
				assert.Len(t, auth.a.TrustedIssuers, 1)
				assert.Contains(t, auth.a.TrustedIssuers, "foobar")
				assert.NoError(t, auth.a.ScopesMatcher.Match([]string{}))
				assert.Equal(t, time.Duration(0), auth.a.ValidityLeeway)
				assert.Empty(t, auth.a.TargetAudiences)

				// assert ttl
				assert.Nil(t, auth.ttl)

				// assert token extractor settings
				assert.IsType(t, extractors.CompositeExtractStrategy{}, auth.ads)
				assert.Contains(t, auth.ads, extractors.HeaderValueExtractStrategy{Name: "Authorization", Prefix: "Bearer"})
				assert.Contains(t, auth.ads, extractors.CookieValueExtractStrategy{Name: "access_token"})
				assert.Contains(t, auth.ads, extractors.QueryParameterExtractStrategy{Name: "access_token"})

				// assert subject factory
				assert.NotNil(t, auth.sf)
			},
		},
	}

	for _, tc := range testCases {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			a, err := newOAuth2IntrospectionAuthenticator(conf)

			// THEN
			tc.assert(t, err, a)
		})
	}
}

func TestCreateOAuth2IntrospectionAuthenticatorFromPrototype(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc              string
		prototypeConfig []byte
		config          []byte
		assert          func(t *testing.T, err error, prototype *oauth2IntrospectionAuthenticator,
			configured *oauth2IntrospectionAuthenticator)
	}{
		{
			uc: "without target config",
			prototypeConfig: []byte(`
introspection_endpoint:
  url: foobar.local
assertions:
  issuers:
    - foobar
session:
  subject_id_from: some_template`),
			assert: func(t *testing.T, err error, prototype *oauth2IntrospectionAuthenticator,
				configured *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, prototype, configured)
			},
		},
		{
			uc: "with unsupported fields",
			prototypeConfig: []byte(`
introspection_endpoint:
  url: foobar.local
assertions:
  issuers:
    - foobar
session:
  subject_id_from: some_template`),
			config: []byte(`foo: bar`),
			assert: func(t *testing.T, err error, _ *oauth2IntrospectionAuthenticator,
				_ *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to unmarshal")
			},
		},
		{
			uc: "with overwrites without cache",
			prototypeConfig: []byte(`
introspection_endpoint:
  url: foobar.local
assertions:
  issuers:
    - foobar
  audience:
    - baz
session:
  subject_id_from: some_template`),
			config: []byte(`
assertions:
  issuers:
    - barfoo
  allowed_algorithms:
    - ES512
`),
			assert: func(t *testing.T, err error, prototype *oauth2IntrospectionAuthenticator,
				configured *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.ads, configured.ads)
				assert.Equal(t, prototype.sf, configured.sf)
				assert.NotEqual(t, prototype.a, configured.a)

				assert.NoError(t, configured.a.ScopesMatcher.Match([]string{}))
				assert.ElementsMatch(t, configured.a.TargetAudiences, []string{"baz"})
				assert.ElementsMatch(t, configured.a.TrustedIssuers, []string{"barfoo"})
				assert.ElementsMatch(t, configured.a.AllowedAlgorithms, []string{string(jose.ES512)})

				assert.Nil(t, prototype.ttl)
				assert.Equal(t, prototype.ttl, configured.ttl)
			},
		},
		{
			uc: "prototype config without cache, target config with cache overwrite",
			prototypeConfig: []byte(`
introspection_endpoint:
  url: foobar.local
assertions:
  issuers:
    - foobar
session:
  subject_id_from: some_template`),
			config: []byte(`cache_ttl: 5s`),
			assert: func(t *testing.T, err error, prototype *oauth2IntrospectionAuthenticator,
				configured *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.ads, configured.ads)
				assert.Equal(t, prototype.sf, configured.sf)
				assert.Equal(t, prototype.a, configured.a)

				assert.Nil(t, prototype.ttl)
				assert.Equal(t, 5*time.Second, *configured.ttl)
			},
		},
		{
			uc: "prototype config with cache, target config with overwrites including cache",
			prototypeConfig: []byte(`
introspection_endpoint:
  url: foobar.local
assertions:
  issuers:
    - foobar
session:
  subject_id_from: some_template
cache_ttl: 5s`),
			config: []byte(`
assertions:
  issuers:
    - barfoo
cache_ttl: 15s
`),
			assert: func(t *testing.T, err error, prototype *oauth2IntrospectionAuthenticator,
				configured *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.ads, configured.ads)
				assert.Equal(t, prototype.sf, configured.sf)
				assert.NotEqual(t, prototype.a, configured.a)
				assert.ElementsMatch(t, configured.a.TrustedIssuers, []string{"barfoo"})

				assert.Equal(t, 5*time.Second, *prototype.ttl)
				assert.Equal(t, 15*time.Second, *configured.ttl)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			pc, err := testsupport.DecodeTestConfig(tc.prototypeConfig)
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			prototype, err := newOAuth2IntrospectionAuthenticator(pc)
			require.NoError(t, err)

			// WHEN
			auth, err := prototype.WithConfig(conf)

			// THEN
			var (
				oaia *oauth2IntrospectionAuthenticator
				ok   bool
			)

			if err == nil {
				oaia, ok = auth.(*oauth2IntrospectionAuthenticator)
				require.True(t, ok)
			}

			tc.assert(t, err, prototype, oaia)
		})
	}
}

// nolint: maintidx
func TestOauth2IntrospectionAuthenticatorExecute(t *testing.T) {
	t.Parallel()

	var (
		endpointCalled bool
		checkRequest   func(req *http.Request)

		responseHeader      map[string]string
		responseContentType string
		responseContent     []byte
		responseCode        int
	)

	zeroTTL := time.Duration(0)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		endpointCalled = true

		checkRequest(r)

		for hn, hv := range responseHeader {
			w.Header().Set(hn, hv)
		}

		if responseContent != nil {
			w.Header().Set("Content-Type", responseContentType)
			w.Header().Set("Content-Length", strconv.Itoa(len(responseContent)))
			_, err := w.Write(responseContent)
			assert.NoError(t, err)
		}

		w.WriteHeader(responseCode)
	}))
	defer srv.Close()

	for _, tc := range []struct {
		uc             string
		authenticator  *oauth2IntrospectionAuthenticator
		instructServer func(t *testing.T)
		configureMocks func(t *testing.T,
			ctx *testsupport.MockContext,
			cch *testsupport.MockCache,
			ads *mockAuthDataGetter,
			auth *oauth2IntrospectionAuthenticator)
		assert func(t *testing.T, err error, sub *subject.Subject)
	}{
		{
			uc:            "with failing auth data source",
			authenticator: &oauth2IntrospectionAuthenticator{},
			configureMocks: func(t *testing.T,
				ctx *testsupport.MockContext,
				cch *testsupport.MockCache,
				ads *mockAuthDataGetter,
				auth *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				ads.On("GetAuthData", ctx).Return(nil, heimdall.ErrCommunicationTimeout)
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.Contains(t, err.Error(), "no access token")
			},
		},
		{
			uc: "with disabled cache and endpoint communication error (dns)",
			authenticator: &oauth2IntrospectionAuthenticator{
				e:   endpoint.Endpoint{URL: "http://heimdall.test.local"},
				ttl: &zeroTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *testsupport.MockContext,
				cch *testsupport.MockCache,
				ads *mockAuthDataGetter,
				auth *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: "test_access_token"}, nil)
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrCommunication)
				assert.Contains(t, err.Error(), "introspection endpoint failed")
			},
		},
		{
			uc: "with disabled cache and unexpected response code from the endpoint",
			authenticator: &oauth2IntrospectionAuthenticator{
				e:   endpoint.Endpoint{URL: srv.URL},
				ttl: &zeroTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *testsupport.MockContext,
				cch *testsupport.MockCache,
				ads *mockAuthDataGetter,
				auth *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: "test_access_token"}, nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				responseCode = http.StatusInternalServerError
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrCommunication)
				assert.Contains(t, err.Error(), "unexpected response code")
			},
		},
		{
			uc: "with disabled cache and failing unmarshalling of the service response",
			authenticator: &oauth2IntrospectionAuthenticator{
				e: endpoint.Endpoint{
					URL:    srv.URL,
					Method: http.MethodPost,
					Headers: map[string]string{
						"Content-Type": "application/x-www-form-urlencoded",
						"Accept":       "application/json",
					},
				},
				ttl: &zeroTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *testsupport.MockContext,
				cch *testsupport.MockCache,
				ads *mockAuthDataGetter,
				auth *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: "test_access_token"}, nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
					assert.Equal(t, http.MethodPost, req.Method)

					assert.NoError(t, req.ParseForm())
					assert.Len(t, req.Form, 2)
					assert.Equal(t, "access_token", req.Form.Get("token_type_hint"))
					assert.Equal(t, "test_access_token", req.Form.Get("token"))
				}

				responseContentType = "text/string"
				responseContent = []byte(`Hi foo`)
				responseCode = http.StatusOK
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "received introspection response")
			},
		},
		{
			uc: "with disabled cache and failing response validation (token not active)",
			authenticator: &oauth2IntrospectionAuthenticator{
				e: endpoint.Endpoint{
					URL:    srv.URL,
					Method: http.MethodPost,
					Headers: map[string]string{
						"Content-Type": "application/x-www-form-urlencoded",
						"Accept":       "application/json",
					},
				},
				a:   oauth2.Expectation{TrustedIssuers: []string{"foobar"}},
				ttl: &zeroTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *testsupport.MockContext,
				cch *testsupport.MockCache,
				ads *mockAuthDataGetter,
				auth *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: "test_access_token"}, nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
					assert.Equal(t, http.MethodPost, req.Method)

					assert.NoError(t, req.ParseForm())
					assert.Len(t, req.Form, 2)
					assert.Equal(t, "access_token", req.Form.Get("token_type_hint"))
					assert.Equal(t, "test_access_token", req.Form.Get("token"))
				}

				rawIntrospectResponse, err := json.Marshal(map[string]any{"active": false})
				require.NoError(t, err)

				responseContentType = "application/json"
				responseContent = rawIntrospectResponse
				responseCode = http.StatusOK
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.Contains(t, err.Error(), "assertion conditions")
			},
		},
		{
			uc: "with disabled cache and failing response validation (issuer not trusted)",
			authenticator: &oauth2IntrospectionAuthenticator{
				e: endpoint.Endpoint{
					URL:    srv.URL,
					Method: http.MethodPost,
					Headers: map[string]string{
						"Content-Type": "application/x-www-form-urlencoded",
						"Accept":       "application/json",
					},
				},
				a:   oauth2.Expectation{TrustedIssuers: []string{"barfoo"}},
				ttl: &zeroTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *testsupport.MockContext,
				cch *testsupport.MockCache,
				ads *mockAuthDataGetter,
				auth *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: "test_access_token"}, nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
					assert.Equal(t, http.MethodPost, req.Method)

					assert.NoError(t, req.ParseForm())
					assert.Len(t, req.Form, 2)
					assert.Equal(t, "access_token", req.Form.Get("token_type_hint"))
					assert.Equal(t, "test_access_token", req.Form.Get("token"))
				}

				rawIntrospectResponse, err := json.Marshal(map[string]any{
					"active":     true,
					"scope":      "foo bar",
					"username":   "unknown",
					"token_type": "Bearer",
					"aud":        "bar",
					"sub":        "foo",
					"iss":        "foobar",
					"iat":        time.Now().Unix(),
					"nbf":        time.Now().Unix(),
					"exp":        time.Now().Unix() + 30,
				})
				require.NoError(t, err)

				responseContentType = "application/json"
				responseContent = rawIntrospectResponse
				responseCode = http.StatusOK
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.Contains(t, err.Error(), "assertion conditions")
			},
		},
		{
			uc: "with disabled cache and successful execution",
			authenticator: &oauth2IntrospectionAuthenticator{
				e: endpoint.Endpoint{
					URL:    srv.URL,
					Method: http.MethodPost,
					Headers: map[string]string{
						"Content-Type": "application/x-www-form-urlencoded",
						"Accept":       "application/json",
					},
				},
				a: oauth2.Expectation{
					TrustedIssuers: []string{"foobar"},
					ScopesMatcher:  oauth2.ExactScopeStrategyMatcher{},
				},
				sf:  &Session{SubjectIDFrom: "sub"},
				ttl: &zeroTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *testsupport.MockContext,
				cch *testsupport.MockCache,
				ads *mockAuthDataGetter,
				auth *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: "test_access_token"}, nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
					assert.Equal(t, http.MethodPost, req.Method)

					assert.NoError(t, req.ParseForm())
					assert.Len(t, req.Form, 2)
					assert.Equal(t, "access_token", req.Form.Get("token_type_hint"))
					assert.Equal(t, "test_access_token", req.Form.Get("token"))
				}

				rawIntrospectResponse, err := json.Marshal(map[string]any{
					"active":     true,
					"scope":      "foo bar",
					"username":   "unknown",
					"token_type": "Bearer",
					"aud":        "bar",
					"sub":        "foo",
					"iss":        "foobar",
					"iat":        time.Now().Unix(),
					"nbf":        time.Now().Unix(),
					"exp":        time.Now().Unix() + 30,
				})
				require.NoError(t, err)

				responseContentType = "application/json"
				responseContent = rawIntrospectResponse
				responseCode = http.StatusOK
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				require.NoError(t, err)

				require.NotNil(t, sub)
				assert.Equal(t, "foo", sub.ID)
				assert.Len(t, sub.Attributes, 10)
				assert.Equal(t, "foo bar", sub.Attributes["scope"])
				assert.Equal(t, true, sub.Attributes["active"])
				assert.Equal(t, "unknown", sub.Attributes["username"])
				assert.Equal(t, "foobar", sub.Attributes["iss"])
				assert.Equal(t, "bar", sub.Attributes["aud"])
				assert.Equal(t, "Bearer", sub.Attributes["token_type"])
				assert.NotEmpty(t, sub.Attributes["nbf"])
				assert.NotEmpty(t, sub.Attributes["iat"])
				assert.NotEmpty(t, sub.Attributes["exp"])
			},
		},
		{
			uc: "with default cache, without cache hit and successful execution",
			authenticator: &oauth2IntrospectionAuthenticator{
				e: endpoint.Endpoint{
					URL:    srv.URL,
					Method: http.MethodPost,
					Headers: map[string]string{
						"Content-Type": "application/x-www-form-urlencoded",
						"Accept":       "application/json",
					},
				},
				a: oauth2.Expectation{
					TrustedIssuers: []string{"foobar"},
					ScopesMatcher:  oauth2.ExactScopeStrategyMatcher{},
				},
				sf: &Session{SubjectIDFrom: "sub"},
			},
			configureMocks: func(t *testing.T,
				ctx *testsupport.MockContext,
				cch *testsupport.MockCache,
				ads *mockAuthDataGetter,
				auth *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				cacheKey := auth.calculateCacheKey("test_access_token")

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: "test_access_token"}, nil)
				cch.On("Get", cacheKey).Return(nil)
				cch.On("Set", cacheKey, mock.Anything, mock.Anything)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
					assert.Equal(t, http.MethodPost, req.Method)

					assert.NoError(t, req.ParseForm())
					assert.Len(t, req.Form, 2)
					assert.Equal(t, "access_token", req.Form.Get("token_type_hint"))
					assert.Equal(t, "test_access_token", req.Form.Get("token"))
				}

				rawIntrospectResponse, err := json.Marshal(map[string]any{
					"active":     true,
					"scope":      "foo bar",
					"username":   "unknown",
					"token_type": "Bearer",
					"aud":        "bar",
					"sub":        "foo",
					"iss":        "foobar",
					"iat":        time.Now().Unix(),
					"nbf":        time.Now().Unix(),
					"exp":        time.Now().Unix() + 30,
				})
				require.NoError(t, err)

				responseContentType = "application/json"
				responseContent = rawIntrospectResponse
				responseCode = http.StatusOK
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				require.NoError(t, err)

				require.NotNil(t, sub)
				assert.Equal(t, "foo", sub.ID)
				assert.Len(t, sub.Attributes, 10)
				assert.Equal(t, "foo bar", sub.Attributes["scope"])
				assert.Equal(t, true, sub.Attributes["active"])
				assert.Equal(t, "unknown", sub.Attributes["username"])
				assert.Equal(t, "foobar", sub.Attributes["iss"])
				assert.Equal(t, "bar", sub.Attributes["aud"])
				assert.Equal(t, "Bearer", sub.Attributes["token_type"])
				assert.NotEmpty(t, sub.Attributes["nbf"])
				assert.NotEmpty(t, sub.Attributes["iat"])
				assert.NotEmpty(t, sub.Attributes["exp"])
			},
		},
		{
			uc: "with default cache, with bad cache hit and successful execution",
			authenticator: &oauth2IntrospectionAuthenticator{
				e: endpoint.Endpoint{
					URL:    srv.URL,
					Method: http.MethodPost,
					Headers: map[string]string{
						"Content-Type": "application/x-www-form-urlencoded",
						"Accept":       "application/json",
					},
				},
				a: oauth2.Expectation{
					TrustedIssuers: []string{"foobar"},
					ScopesMatcher:  oauth2.ExactScopeStrategyMatcher{},
				},
				sf: &Session{SubjectIDFrom: "sub"},
			},
			configureMocks: func(t *testing.T,
				ctx *testsupport.MockContext,
				cch *testsupport.MockCache,
				ads *mockAuthDataGetter,
				auth *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				cacheKey := auth.calculateCacheKey("test_access_token")

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: "test_access_token"}, nil)
				cch.On("Get", cacheKey).Return(zeroTTL)
				cch.On("Delete", cacheKey)
				cch.On("Set", cacheKey, mock.Anything, mock.Anything)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
					assert.Equal(t, http.MethodPost, req.Method)

					assert.NoError(t, req.ParseForm())
					assert.Len(t, req.Form, 2)
					assert.Equal(t, "access_token", req.Form.Get("token_type_hint"))
					assert.Equal(t, "test_access_token", req.Form.Get("token"))
				}

				rawIntrospectResponse, err := json.Marshal(map[string]any{
					"active":     true,
					"scope":      "foo bar",
					"username":   "unknown",
					"token_type": "Bearer",
					"aud":        "bar",
					"sub":        "foo",
					"iss":        "foobar",
					"iat":        time.Now().Unix(),
					"nbf":        time.Now().Unix(),
					"exp":        time.Now().Unix() + 30,
				})
				require.NoError(t, err)

				responseContentType = "application/json"
				responseContent = rawIntrospectResponse
				responseCode = http.StatusOK
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				require.NoError(t, err)

				require.NotNil(t, sub)
				assert.Equal(t, "foo", sub.ID)
				assert.Len(t, sub.Attributes, 10)
				assert.Equal(t, "foo bar", sub.Attributes["scope"])
				assert.Equal(t, true, sub.Attributes["active"])
				assert.Equal(t, "unknown", sub.Attributes["username"])
				assert.Equal(t, "foobar", sub.Attributes["iss"])
				assert.Equal(t, "bar", sub.Attributes["aud"])
				assert.Equal(t, "Bearer", sub.Attributes["token_type"])
				assert.NotEmpty(t, sub.Attributes["nbf"])
				assert.NotEmpty(t, sub.Attributes["iat"])
				assert.NotEmpty(t, sub.Attributes["exp"])
			},
		},
		{
			uc: "with default cache, with cache hit and successful execution",
			authenticator: &oauth2IntrospectionAuthenticator{
				e: endpoint.Endpoint{
					URL:    srv.URL,
					Method: http.MethodPost,
					Headers: map[string]string{
						"Content-Type": "application/x-www-form-urlencoded",
						"Accept":       "application/json",
					},
				},
				a: oauth2.Expectation{
					TrustedIssuers: []string{"foobar"},
					ScopesMatcher:  oauth2.ExactScopeStrategyMatcher{},
				},
				sf: &Session{SubjectIDFrom: "sub"},
			},
			configureMocks: func(t *testing.T,
				ctx *testsupport.MockContext,
				cch *testsupport.MockCache,
				ads *mockAuthDataGetter,
				auth *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				cacheKey := auth.calculateCacheKey("test_access_token")

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: "test_access_token"}, nil)

				rawIntrospectResponse, err := json.Marshal(map[string]any{
					"active":     true,
					"scope":      "foo bar",
					"username":   "unknown",
					"token_type": "Bearer",
					"aud":        "bar",
					"sub":        "foo",
					"iss":        "foobar",
					"iat":        time.Now().Unix(),
					"nbf":        time.Now().Unix(),
					"exp":        time.Now().Unix() + 30,
				})
				require.NoError(t, err)

				cch.On("Get", cacheKey).Return(rawIntrospectResponse)
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				require.NoError(t, err)

				require.NotNil(t, sub)
				assert.Equal(t, "foo", sub.ID)
				assert.Len(t, sub.Attributes, 10)
				assert.Equal(t, "foo bar", sub.Attributes["scope"])
				assert.Equal(t, true, sub.Attributes["active"])
				assert.Equal(t, "unknown", sub.Attributes["username"])
				assert.Equal(t, "foobar", sub.Attributes["iss"])
				assert.Equal(t, "bar", sub.Attributes["aud"])
				assert.Equal(t, "Bearer", sub.Attributes["token_type"])
				assert.NotEmpty(t, sub.Attributes["nbf"])
				assert.NotEmpty(t, sub.Attributes["iat"])
				assert.NotEmpty(t, sub.Attributes["exp"])
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			endpointCalled = false
			responseHeader = nil
			responseContentType = ""
			responseContent = nil

			checkRequest = func(req *http.Request) { t.Helper() }

			instructServer := x.IfThenElse(tc.instructServer != nil,
				tc.instructServer,
				func(t *testing.T) { t.Helper() })

			configureMocks := x.IfThenElse(tc.configureMocks != nil,
				tc.configureMocks,
				func(t *testing.T,
					ctx *testsupport.MockContext,
					cch *testsupport.MockCache,
					ads *mockAuthDataGetter,
					auth *oauth2IntrospectionAuthenticator,
				) {
					t.Helper()
				})

			ads := &mockAuthDataGetter{}
			tc.authenticator.ads = ads

			cch := &testsupport.MockCache{}

			ctx := &testsupport.MockContext{}
			ctx.On("AppContext").Return(cache.WithContext(context.Background(), cch))

			configureMocks(t, ctx, cch, ads, tc.authenticator)
			instructServer(t)

			// WHEN
			sub, err := tc.authenticator.Execute(ctx)

			// THEN
			tc.assert(t, err, sub)

			ctx.AssertExpectations(t)
			cch.AssertExpectations(t)
			ads.AssertExpectations(t)
		})
	}
}

func TestCacheTTLCalculation(t *testing.T) {
	t.Parallel()

	negativeTTL := -1 * time.Second
	zeroTTL := 0 * time.Second
	positiveSmallTTL := 10 * time.Second
	positiveBigTTL := 10 * time.Minute

	for _, tc := range []struct {
		uc            string
		authenticator *oauth2IntrospectionAuthenticator
		response      func() *oauth2.IntrospectionResponse
		assert        func(t *testing.T, ttl time.Duration)
	}{
		{
			uc:            "default (nil) ttl settings and no exp in response",
			authenticator: &oauth2IntrospectionAuthenticator{},
			response:      func() *oauth2.IntrospectionResponse { return &oauth2.IntrospectionResponse{} },
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, zeroTTL, ttl)
			},
		},
		{
			uc:            "default (nil) ttl settings and exp in response which would result in negative ttl with 10s leeway",
			authenticator: &oauth2IntrospectionAuthenticator{},
			response: func() *oauth2.IntrospectionResponse {
				expiry := oauth2.NumericDate(time.Now().Add(8 * time.Second).Unix())
				resp := &oauth2.IntrospectionResponse{}
				resp.Expiry = &expiry

				return resp
			},
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, zeroTTL, ttl)
			},
		},
		{
			uc:            "default (nil) ttl settings and exp in response which would result in 0 ttl with 10s leeway",
			authenticator: &oauth2IntrospectionAuthenticator{},
			response: func() *oauth2.IntrospectionResponse {
				expiry := oauth2.NumericDate(time.Now().Add(10 * time.Second).Unix())
				resp := &oauth2.IntrospectionResponse{}
				resp.Expiry = &expiry

				return resp
			},
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, zeroTTL, ttl)
			},
		},
		{
			uc:            "default (nil) ttl settings and exp in response which would result in positive ttl with 10s leeway",
			authenticator: &oauth2IntrospectionAuthenticator{},
			response: func() *oauth2.IntrospectionResponse {
				expiry := oauth2.NumericDate(time.Now().Add(12 * time.Second).Unix())
				resp := &oauth2.IntrospectionResponse{}
				resp.Expiry = &expiry

				return resp
			},
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, 2*time.Second, ttl)
			},
		},
		{
			uc:            "negative ttl settings and exp not set in response",
			authenticator: &oauth2IntrospectionAuthenticator{ttl: &negativeTTL},
			response:      func() *oauth2.IntrospectionResponse { return &oauth2.IntrospectionResponse{} },
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, zeroTTL, ttl)
			},
		},
		{
			uc:            "zero ttl settings and exp not set in response",
			authenticator: &oauth2IntrospectionAuthenticator{ttl: &zeroTTL},
			response:      func() *oauth2.IntrospectionResponse { return &oauth2.IntrospectionResponse{} },
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, zeroTTL, ttl)
			},
		},
		{
			uc:            "positive ttl settings and exp not set in response",
			authenticator: &oauth2IntrospectionAuthenticator{ttl: &positiveSmallTTL},
			response:      func() *oauth2.IntrospectionResponse { return &oauth2.IntrospectionResponse{} },
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, positiveSmallTTL, ttl)
			},
		},
		{
			// nolint: lll
			uc:            "negative ttl settings and exp set to a value response, which would result in positive ttl with 10s leeway",
			authenticator: &oauth2IntrospectionAuthenticator{ttl: &negativeTTL},
			response: func() *oauth2.IntrospectionResponse {
				expiry := oauth2.NumericDate(time.Now().Add(15 * time.Second).Unix())
				resp := &oauth2.IntrospectionResponse{}
				resp.Expiry = &expiry

				return resp
			},
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, zeroTTL, ttl)
			},
		},
		{
			uc:            "zero ttl settings and exp set to a value response, which would result in 0s ttl with 10s leeway",
			authenticator: &oauth2IntrospectionAuthenticator{ttl: &negativeTTL},
			response: func() *oauth2.IntrospectionResponse {
				expiry := oauth2.NumericDate(time.Now().Add(10 * time.Second).Unix())
				resp := &oauth2.IntrospectionResponse{}
				resp.Expiry = &expiry

				return resp
			},
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, zeroTTL, ttl)
			},
		},
		{
			// nolint: lll
			uc:            "zero ttl settings and exp set to a value response, which would result in positive ttl with 10s leeway",
			authenticator: &oauth2IntrospectionAuthenticator{ttl: &negativeTTL},
			response: func() *oauth2.IntrospectionResponse {
				expiry := oauth2.NumericDate(time.Now().Add(12 * time.Second).Unix())
				resp := &oauth2.IntrospectionResponse{}
				resp.Expiry = &expiry

				return resp
			},
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, zeroTTL, ttl)
			},
		},
		{
			uc:            "ttl settings smaller compared to ttl calculation on exp set in response",
			authenticator: &oauth2IntrospectionAuthenticator{ttl: &positiveSmallTTL},
			response: func() *oauth2.IntrospectionResponse {
				expiry := oauth2.NumericDate(time.Now().Add(12 * time.Minute).Unix())
				resp := &oauth2.IntrospectionResponse{}
				resp.Expiry = &expiry

				return resp
			},
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, positiveSmallTTL, ttl)
			},
		},
		{
			uc:            "ttl settings bigger compared to ttl calculation on exp set in response",
			authenticator: &oauth2IntrospectionAuthenticator{ttl: &positiveBigTTL},
			response: func() *oauth2.IntrospectionResponse {
				expiry := oauth2.NumericDate(time.Now().Add(15 * time.Second).Unix())
				resp := &oauth2.IntrospectionResponse{}
				resp.Expiry = &expiry

				return resp
			},
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, 5*time.Second, ttl)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			ttl := tc.authenticator.getCacheTTL(tc.response())

			// THEN
			tc.assert(t, ttl)
		})
	}
}
