package authenticators

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/heimdall"
	heimdallmocks "github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/pipeline/authenticators/extractors"
	"github.com/dadrus/heimdall/internal/pipeline/endpoint"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/testsupport"
	"github.com/dadrus/heimdall/internal/x"
)

func TestCreateGenericAuthenticator(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc          string
		config      []byte
		assertError func(t *testing.T, err error, auth *genericAuthenticator)
	}{
		{
			uc: "config with undefined fields",
			config: []byte(`
foo: bar
identity_info_endpoint:
  url: http://test.com
session:
  subject_id_from: some_template`),
			assertError: func(t *testing.T, err error, auth *genericAuthenticator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to decode")
			},
		},
		{
			uc: "missing url config",
			config: []byte(`
authentication_data_source:
  - header: foo-header
session:
  subject_id_from: some_template`),
			assertError: func(t *testing.T, err error, auth *genericAuthenticator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "endpoint configuration")
			},
		},
		{
			uc: "missing session config",
			config: []byte(`
identity_info_endpoint:
  url: http://test.com
authentication_data_source:
  - header: foo-header`),
			assertError: func(t *testing.T, err error, auth *genericAuthenticator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "session configuration")
			},
		},
		{
			uc: "missing authentication data source config",
			config: []byte(`
identity_info_endpoint:
  url: http://test.com
session:
  subject_id_from: some_template`),
			assertError: func(t *testing.T, err error, auth *genericAuthenticator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "authentication_data_source")
			},
		},
		{
			uc: "with valid configuration but disabled cache",
			config: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: GET
authentication_data_source:
  - header: foo-header
session:
  subject_id_from: some_template`),
			assertError: func(t *testing.T, err error, auth *genericAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, auth)
				assert.Equal(t, "http://test.com", auth.e.URL)
				assert.Equal(t, http.MethodGet, auth.e.Method)
				ces, ok := auth.ads.(extractors.CompositeExtractStrategy)
				assert.True(t, ok)
				assert.Len(t, ces, 1)
				assert.Contains(t, ces, &extractors.HeaderValueExtractStrategy{Name: "foo-header"})
				assert.Equal(t, &Session{SubjectIDFrom: "some_template"}, auth.sf)
				assert.Equal(t, time.Duration(0), auth.ttl)
				assert.False(t, auth.IsFallbackOnErrorAllowed())
			},
		},
		{
			uc: "with valid configuration and enabled cache",
			config: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - cookie: foo-cookie
session:
  subject_id_from: some_template
cache_ttl: 5s`),
			assertError: func(t *testing.T, err error, auth *genericAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, auth)
				assert.Equal(t, "http://test.com", auth.e.URL)
				assert.Equal(t, http.MethodPost, auth.e.Method)
				ces, ok := auth.ads.(extractors.CompositeExtractStrategy)
				assert.True(t, ok)
				assert.Len(t, ces, 1)
				assert.Contains(t, ces, &extractors.CookieValueExtractStrategy{Name: "foo-cookie"})
				assert.Equal(t, &Session{SubjectIDFrom: "some_template"}, auth.sf)
				assert.Equal(t, 5*time.Second, auth.ttl)
				assert.False(t, auth.IsFallbackOnErrorAllowed())
			},
		},
		{
			uc: "with valid configuration enabling fallback on errors",
			config: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - cookie: foo-cookie
session:
  subject_id_from: some_template
allow_fallback_on_error: true`),
			assertError: func(t *testing.T, err error, auth *genericAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, auth)
				assert.Equal(t, "http://test.com", auth.e.URL)
				assert.Equal(t, http.MethodPost, auth.e.Method)
				ces, ok := auth.ads.(extractors.CompositeExtractStrategy)
				assert.True(t, ok)
				assert.Len(t, ces, 1)
				assert.Contains(t, ces, &extractors.CookieValueExtractStrategy{Name: "foo-cookie"})
				assert.Equal(t, &Session{SubjectIDFrom: "some_template"}, auth.sf)
				assert.Equal(t, time.Duration(0), auth.ttl)
				assert.True(t, auth.IsFallbackOnErrorAllowed())
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			auth, err := newGenericAuthenticator(conf)

			// THEN
			tc.assertError(t, err, auth)
		})
	}
}

func TestCreateGenericAuthenticatorFromPrototype(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc              string
		prototypeConfig []byte
		config          []byte
		assert          func(t *testing.T, err error, prototype *genericAuthenticator,
			configured *genericAuthenticator)
	}{
		{
			uc: "prototype config without cache configured and empty target config",
			prototypeConfig: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
session:
  subject_id_from: some_template
allow_fallback_on_error: true`),
			assert: func(t *testing.T, err error, prototype *genericAuthenticator,
				configured *genericAuthenticator,
			) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, prototype, configured)
			},
		},
		{
			uc: "with unsupported fields in target config",
			prototypeConfig: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
session:
  subject_id_from: some_template`),
			config: []byte(`foo: bar`),
			assert: func(t *testing.T, err error, prototype *genericAuthenticator,
				configured *genericAuthenticator,
			) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to parse")
			},
		},
		{
			uc: "prototype config without cache, config with cache",
			prototypeConfig: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
session:
  subject_id_from: some_template`),
			config: []byte(`cache_ttl: 5s`),
			assert: func(t *testing.T, err error, prototype *genericAuthenticator,
				configured *genericAuthenticator,
			) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.ads, configured.ads)
				assert.Equal(t, prototype.sf, configured.sf)
				assert.Equal(t, time.Duration(0), prototype.ttl)
				assert.NotEqual(t, prototype.ttl, configured.ttl)
				assert.Equal(t, 5*time.Second, configured.ttl)
				assert.Equal(t, prototype.IsFallbackOnErrorAllowed(), configured.IsFallbackOnErrorAllowed())
			},
		},
		{
			uc: "prototype config with disabled fallback on error, config with enabled fallback on error",
			prototypeConfig: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
session:
  subject_id_from: some_template`),
			config: []byte(`allow_fallback_on_error: true`),
			assert: func(t *testing.T, err error, prototype *genericAuthenticator,
				configured *genericAuthenticator,
			) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.ads, configured.ads)
				assert.Equal(t, prototype.sf, configured.sf)
				assert.Equal(t, prototype.ttl, configured.ttl)
				assert.NotEqual(t, prototype.IsFallbackOnErrorAllowed(), configured.IsFallbackOnErrorAllowed())
				assert.True(t, configured.IsFallbackOnErrorAllowed())
			},
		},
		{
			uc: "prototype config with cache ttl, config with cache tll",
			prototypeConfig: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
session:
  subject_id_from: some_template
cache_ttl: 5s`),
			config: []byte(`
cache_ttl: 15s`),
			assert: func(t *testing.T, err error, prototype *genericAuthenticator,
				configured *genericAuthenticator,
			) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.ads, configured.ads)
				assert.Equal(t, prototype.sf, configured.sf)
				assert.NotEqual(t, prototype.ttl, configured.ttl)
				assert.Equal(t, 15*time.Second, configured.ttl)
				assert.Equal(t, 5*time.Second, prototype.ttl)
				assert.Equal(t, prototype.IsFallbackOnErrorAllowed(), configured.IsFallbackOnErrorAllowed())
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			pc, err := testsupport.DecodeTestConfig(tc.prototypeConfig)
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			prototype, err := newGenericAuthenticator(pc)
			require.NoError(t, err)

			// WHEN
			auth, err := prototype.WithConfig(conf)

			// THEN
			var (
				genAuth *genericAuthenticator
				ok      bool
			)

			if err == nil {
				genAuth, ok = auth.(*genericAuthenticator)
				require.True(t, ok)
			}

			tc.assert(t, err, prototype, genAuth)
		})
	}
}

// nolint: maintidx
func TestGenericAuthenticatorExecute(t *testing.T) {
	t.Parallel()

	var (
		endpointCalled bool
		checkRequest   func(req *http.Request)

		responseHeaders     map[string]string
		responseContentType string
		responseContent     []byte
		responseCode        int
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		endpointCalled = true

		checkRequest(r)

		for hn, hv := range responseHeaders {
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
		authenticator  *genericAuthenticator
		instructServer func(t *testing.T)
		configureMocks func(t *testing.T,
			ctx *heimdallmocks.MockContext,
			cch *mocks.MockCache,
			ads *mockAuthDataGetter,
			auth *genericAuthenticator)
		assert func(t *testing.T, err error, sub *subject.Subject)
	}{
		{
			uc:            "with failing auth data source",
			authenticator: &genericAuthenticator{},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.MockContext,
				cch *mocks.MockCache,
				ads *mockAuthDataGetter,
				auth *genericAuthenticator,
			) {
				t.Helper()

				ads.On("GetAuthData", ctx).Return(nil, heimdall.ErrCommunicationTimeout)
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.Contains(t, err.Error(), "failed to get authentication data")
			},
		},
		{
			uc: "with endpoint communication error (dns)",
			authenticator: &genericAuthenticator{
				e: endpoint.Endpoint{URL: "http://heimdall.test.local"},
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.MockContext,
				cch *mocks.MockCache,
				ads *mockAuthDataGetter,
				auth *genericAuthenticator,
			) {
				t.Helper()

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: "session_token"}, nil)
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrCommunication)
				assert.Contains(t, err.Error(), "request to the endpoint")
			},
		},
		{
			uc: "with unexpected response code from server",
			authenticator: &genericAuthenticator{
				e: endpoint.Endpoint{URL: srv.URL},
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.MockContext,
				cch *mocks.MockCache,
				ads *mockAuthDataGetter,
				auth *genericAuthenticator,
			) {
				t.Helper()

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: "session_token"}, nil)
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
			uc: "with error while extracting subject information",
			authenticator: &genericAuthenticator{
				e: endpoint.Endpoint{
					URL:    srv.URL,
					Method: http.MethodGet,
					Headers: map[string]string{
						"Accept": "application/json",
					},
				},
				sf: &Session{SubjectIDFrom: "barfoo"},
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.MockContext,
				cch *mocks.MockCache,
				ads *mockAuthDataGetter,
				auth *genericAuthenticator,
			) {
				t.Helper()

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: "session_token"}, nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, http.MethodGet, req.Method)
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
					assert.Equal(t, "session_token", req.Header.Get("Dummy"))
				}

				responseCode = http.StatusOK
				responseContent = []byte(`{ "user_id": "barbar" }`)
				responseContentType = "application/json"
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed to extract subject")
			},
		},
		{
			uc: "successful execution without cache usage",
			authenticator: &genericAuthenticator{
				e: endpoint.Endpoint{
					URL:    srv.URL,
					Method: http.MethodGet,
					Headers: map[string]string{
						"Accept": "application/json",
					},
				},
				sf: &Session{SubjectIDFrom: "user_id"},
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.MockContext,
				cch *mocks.MockCache,
				ads *mockAuthDataGetter,
				auth *genericAuthenticator,
			) {
				t.Helper()

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: "session_token"}, nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, http.MethodGet, req.Method)
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
					assert.Equal(t, "session_token", req.Header.Get("Dummy"))
				}

				responseCode = http.StatusOK
				responseContent = []byte(`{ "user_id": "barbar" }`)
				responseContentType = "application/json"
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				require.NoError(t, err)

				require.NotNil(t, sub)
				assert.Equal(t, "barbar", sub.ID)
				assert.Len(t, sub.Attributes, 1)
			},
		},
		{
			uc: "successful execution with bad cache hit",
			authenticator: &genericAuthenticator{
				e: endpoint.Endpoint{
					URL:    srv.URL,
					Method: http.MethodGet,
					Headers: map[string]string{
						"Accept": "application/json",
					},
				},
				sf:  &Session{SubjectIDFrom: "user_id"},
				ttl: 5 * time.Second,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.MockContext,
				cch *mocks.MockCache,
				ads *mockAuthDataGetter,
				auth *genericAuthenticator,
			) {
				t.Helper()

				cacheKey := auth.calculateCacheKey("session_token")

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: "session_token"}, nil)
				cch.On("Get", cacheKey).Return(time.Duration(10))
				cch.On("Delete", cacheKey)
				cch.On("Set", cacheKey, []byte(`{ "user_id": "barbar" }`), auth.ttl)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, http.MethodGet, req.Method)
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
					assert.Equal(t, "session_token", req.Header.Get("Dummy"))
				}

				responseCode = http.StatusOK
				responseContent = []byte(`{ "user_id": "barbar" }`)
				responseContentType = "application/json"
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				require.NoError(t, err)

				require.NotNil(t, sub)
				assert.Equal(t, "barbar", sub.ID)
				assert.Len(t, sub.Attributes, 1)
			},
		},
		{
			uc: "successful execution with positive cache hit",
			authenticator: &genericAuthenticator{
				e: endpoint.Endpoint{
					URL:    srv.URL,
					Method: http.MethodGet,
					Headers: map[string]string{
						"Accept": "application/json",
					},
				},
				sf:  &Session{SubjectIDFrom: "user_id"},
				ttl: 5 * time.Second,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.MockContext,
				cch *mocks.MockCache,
				ads *mockAuthDataGetter,
				auth *genericAuthenticator,
			) {
				t.Helper()

				cacheKey := auth.calculateCacheKey("session_token")

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: "session_token"}, nil)
				cch.On("Get", cacheKey).Return([]byte(`{ "user_id": "barbar" }`))
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				require.NoError(t, err)

				require.NotNil(t, sub)
				assert.Equal(t, "barbar", sub.ID)
				assert.Len(t, sub.Attributes, 1)
			},
		},
		{
			uc: "successful execution with negative cache hit",
			authenticator: &genericAuthenticator{
				e: endpoint.Endpoint{
					URL:    srv.URL,
					Method: http.MethodGet,
					Headers: map[string]string{
						"Accept": "application/json",
					},
				},
				sf:  &Session{SubjectIDFrom: "user_id"},
				ttl: 5 * time.Second,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.MockContext,
				cch *mocks.MockCache,
				ads *mockAuthDataGetter,
				auth *genericAuthenticator,
			) {
				t.Helper()

				cacheKey := auth.calculateCacheKey("session_token")

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: "session_token"}, nil)
				cch.On("Get", cacheKey).Return(nil)
				cch.On("Set", cacheKey, []byte(`{ "user_id": "barbar" }`), auth.ttl)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, http.MethodGet, req.Method)
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
					assert.Equal(t, "session_token", req.Header.Get("Dummy"))
				}

				responseCode = http.StatusOK
				responseContent = []byte(`{ "user_id": "barbar" }`)
				responseContentType = "application/json"
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				require.NoError(t, err)

				require.NotNil(t, sub)
				assert.Equal(t, "barbar", sub.ID)
				assert.Len(t, sub.Attributes, 1)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			endpointCalled = false
			responseHeaders = nil
			responseContentType = ""
			responseContent = nil

			checkRequest = func(*http.Request) { t.Helper() }

			instructServer := x.IfThenElse(tc.instructServer != nil,
				tc.instructServer,
				func(t *testing.T) { t.Helper() })

			configureMocks := x.IfThenElse(tc.configureMocks != nil,
				tc.configureMocks,
				func(t *testing.T,
					_ *heimdallmocks.MockContext,
					_ *mocks.MockCache,
					_ *mockAuthDataGetter,
					_ *genericAuthenticator,
				) {
					t.Helper()
				})

			ads := &mockAuthDataGetter{}
			tc.authenticator.ads = ads

			cch := &mocks.MockCache{}

			ctx := &heimdallmocks.MockContext{}
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
