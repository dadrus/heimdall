package authenticators

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/endpoint"
	"github.com/dadrus/heimdall/internal/heimdall"
	heimdallmocks "github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators/extractors"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/testsupport"
	"github.com/dadrus/heimdall/internal/x"
)

func TestGenericAuthenticatorCreate(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc          string
		id          string
		config      []byte
		assertError func(t *testing.T, err error, auth *genericAuthenticator)
	}{
		{
			uc: "config with undefined fields",
			config: []byte(`
foo: bar
identity_info_endpoint:
  url: http://test.com
subject:
  id: some_template`),
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
subject:
  id: some_template`),
			assertError: func(t *testing.T, err error, auth *genericAuthenticator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "endpoint configuration")
			},
		},
		{
			uc: "missing subject config",
			config: []byte(`
identity_info_endpoint:
  url: http://test.com
authentication_data_source:
  - header: foo-header`),
			assertError: func(t *testing.T, err error, auth *genericAuthenticator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "subject configuration")
			},
		},
		{
			uc: "missing authentication data source config",
			config: []byte(`
identity_info_endpoint:
  url: http://test.com
subject:
  id: some_template`),
			assertError: func(t *testing.T, err error, auth *genericAuthenticator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "authentication_data_source")
			},
		},
		{
			uc: "with valid configuration but disabled cache",
			id: "auth1",
			config: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: GET
authentication_data_source:
  - header: foo-header
subject:
  id: some_template`),
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
				assert.Equal(t, &SubjectInfo{IDFrom: "some_template"}, auth.sf)
				assert.Equal(t, time.Duration(0), auth.ttl)
				assert.False(t, auth.IsFallbackOnErrorAllowed())
				assert.Nil(t, auth.sessionLifespanConf)
				assert.Equal(t, "auth1", auth.HandlerID())
			},
		},
		{
			uc: "with valid configuration and enabled cache",
			id: "auth1",
			config: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - cookie: foo-cookie
subject:
  id: some_template
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
				assert.Equal(t, &SubjectInfo{IDFrom: "some_template"}, auth.sf)
				assert.Equal(t, 5*time.Second, auth.ttl)
				assert.False(t, auth.IsFallbackOnErrorAllowed())
				assert.Nil(t, auth.sessionLifespanConf)
				assert.Equal(t, "auth1", auth.HandlerID())
			},
		},
		{
			uc: "with valid configuration enabling fallback on errors",
			id: "auth1",
			config: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - cookie: foo-cookie
subject:
  id: some_template
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
				assert.Equal(t, &SubjectInfo{IDFrom: "some_template"}, auth.sf)
				assert.Equal(t, time.Duration(0), auth.ttl)
				assert.True(t, auth.IsFallbackOnErrorAllowed())
				assert.Nil(t, auth.sessionLifespanConf)
				assert.Equal(t, "auth1", auth.HandlerID())
			},
		},
		{
			uc: "with session lifespan config",
			id: "auth1",
			config: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: PATCH
authentication_data_source:
  - cookie: foo-cookie
subject:
  id: some_template
session_lifespan:
  active: foo
  issued_at: bar
  not_before: baz
  not_after: zab
  time_format: foo bar
  validity_leeway: 2s`),
			assertError: func(t *testing.T, err error, auth *genericAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, auth)
				assert.Equal(t, "http://test.com", auth.e.URL)
				assert.Equal(t, http.MethodPatch, auth.e.Method)
				ces, ok := auth.ads.(extractors.CompositeExtractStrategy)
				assert.True(t, ok)
				assert.Len(t, ces, 1)
				assert.Contains(t, ces, &extractors.CookieValueExtractStrategy{Name: "foo-cookie"})
				assert.Equal(t, &SubjectInfo{IDFrom: "some_template"}, auth.sf)
				assert.Equal(t, time.Duration(0), auth.ttl)
				assert.False(t, auth.IsFallbackOnErrorAllowed())
				assert.NotNil(t, auth.sessionLifespanConf)
				assert.Equal(t, "foo", auth.sessionLifespanConf.ActiveField)
				assert.Equal(t, "bar", auth.sessionLifespanConf.IssuedAtField)
				assert.Equal(t, "baz", auth.sessionLifespanConf.NotBeforeField)
				assert.Equal(t, "zab", auth.sessionLifespanConf.NotAfterField)
				assert.Equal(t, "foo bar", auth.sessionLifespanConf.TimeFormat)
				assert.Equal(t, 2*time.Second, auth.sessionLifespanConf.ValidityLeeway)
				assert.Equal(t, "auth1", auth.HandlerID())
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			auth, err := newGenericAuthenticator(tc.id, conf)

			// THEN
			tc.assertError(t, err, auth)
		})
	}
}

func TestGenericAuthenticatorWithConfig(t *testing.T) { // nolint: maintidx
	t.Parallel()

	for _, tc := range []struct {
		uc              string
		id              string
		prototypeConfig []byte
		config          []byte
		assert          func(t *testing.T, err error, prototype *genericAuthenticator,
			configured *genericAuthenticator)
	}{
		{
			uc: "prototype config without cache configured and empty target config",
			id: "auth2",
			prototypeConfig: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
subject:
  id: some_template
allow_fallback_on_error: true`),
			assert: func(t *testing.T, err error, prototype *genericAuthenticator,
				configured *genericAuthenticator,
			) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, prototype, configured)
				assert.Equal(t, "auth2", configured.HandlerID())
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
subject:
  id: some_template`),
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
			id: "auth2",
			prototypeConfig: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
subject:
  id: some_template`),
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
				assert.Equal(t, prototype.sessionLifespanConf, configured.sessionLifespanConf)
				assert.Equal(t, "auth2", configured.HandlerID())
			},
		},
		{
			uc: "prototype config with disabled fallback on error, config with enabled fallback on error",
			id: "auth2",
			prototypeConfig: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
subject:
  id: some_template`),
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
				assert.Equal(t, prototype.sessionLifespanConf, configured.sessionLifespanConf)
				assert.Equal(t, "auth2", configured.HandlerID())
			},
		},
		{
			uc: "prototype config with cache ttl, config with cache tll",
			id: "auth2",
			prototypeConfig: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
subject:
  id: some_template
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
				assert.Equal(t, prototype.sessionLifespanConf, configured.sessionLifespanConf)
				assert.Equal(t, "auth2", configured.HandlerID())
			},
		},
		{
			uc: "prototype with session lifespan config and empty target config",
			id: "auth2",
			prototypeConfig: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
subject:
  id: some_template
cache_ttl: 5s
session_lifespan:
  active: foo
  issued_at: bar
  not_before: baz
  not_after: zab
  time_format: foo bar
  validity_leeway: 2s`),
			assert: func(t *testing.T, err error, prototype *genericAuthenticator,
				configured *genericAuthenticator,
			) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.ads, configured.ads)
				assert.Equal(t, prototype.sf, configured.sf)
				assert.Equal(t, prototype.ttl, configured.ttl)
				assert.Equal(t, prototype.IsFallbackOnErrorAllowed(), configured.IsFallbackOnErrorAllowed())
				assert.Equal(t, prototype.sessionLifespanConf, configured.sessionLifespanConf)
				assert.NotNil(t, configured.sessionLifespanConf)
				assert.Equal(t, "foo", configured.sessionLifespanConf.ActiveField)
				assert.Equal(t, "bar", configured.sessionLifespanConf.IssuedAtField)
				assert.Equal(t, "baz", configured.sessionLifespanConf.NotBeforeField)
				assert.Equal(t, "zab", configured.sessionLifespanConf.NotAfterField)
				assert.Equal(t, "foo bar", configured.sessionLifespanConf.TimeFormat)
				assert.Equal(t, 2*time.Second, configured.sessionLifespanConf.ValidityLeeway)
				assert.Equal(t, "auth2", configured.HandlerID())
			},
		},
		{
			uc: "reconfiguration of identity_info_endpoint not possible",
			prototypeConfig: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
subject:
  id: some_template`),
			config: []byte(`
identity_info_endpoint:
  url: http://foo.bar
`),
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
			uc: "reconfiguration of authentication_data_source not possible",
			prototypeConfig: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
subject:
  id: some_template`),
			config: []byte(`
authentication_data_source:
  - header: bar-header
`),
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
			uc: "reconfiguration of subject not possible",
			prototypeConfig: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
subject:
  id: some_template`),
			config: []byte(`
subject:
  id: new_template
`),
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
			uc: "reconfiguration of session_lifespan not possible",
			prototypeConfig: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
subject:
  id: some_template`),
			config: []byte(`
session_lifespan:
  active: foo
`),
			assert: func(t *testing.T, err error, prototype *genericAuthenticator,
				configured *genericAuthenticator,
			) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to parse")
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			pc, err := testsupport.DecodeTestConfig(tc.prototypeConfig)
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			prototype, err := newGenericAuthenticator(tc.id, pc)
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

	type HandlerIdentifier interface {
		HandlerID() string
	}

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
			authenticator: &genericAuthenticator{id: "auth3"},
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

				var identifier HandlerIdentifier
				require.True(t, errors.As(err, &identifier))
				assert.Equal(t, "auth3", identifier.HandlerID())
			},
		},
		{
			uc: "with endpoint communication error (dns)",
			authenticator: &genericAuthenticator{
				id: "auth3",
				e:  endpoint.Endpoint{URL: "http://heimdall.test.local"},
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

				var identifier HandlerIdentifier
				require.True(t, errors.As(err, &identifier))
				assert.Equal(t, "auth3", identifier.HandlerID())
			},
		},
		{
			uc: "with unexpected response code from server",
			authenticator: &genericAuthenticator{
				id: "auth3",
				e:  endpoint.Endpoint{URL: srv.URL},
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

				var identifier HandlerIdentifier
				require.True(t, errors.As(err, &identifier))
				assert.Equal(t, "auth3", identifier.HandlerID())
			},
		},
		{
			uc: "with error while extracting subject information",
			authenticator: &genericAuthenticator{
				id: "auth3",
				e: endpoint.Endpoint{
					URL:    srv.URL,
					Method: http.MethodGet,
					Headers: map[string]string{
						"Accept": "application/json",
					},
				},
				sf: &SubjectInfo{IDFrom: "barfoo"},
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

				var identifier HandlerIdentifier
				require.True(t, errors.As(err, &identifier))
				assert.Equal(t, "auth3", identifier.HandlerID())
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
				sf: &SubjectInfo{IDFrom: "user_id"},
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
				sf:  &SubjectInfo{IDFrom: "user_id"},
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
				sf:  &SubjectInfo{IDFrom: "user_id"},
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
				sf:  &SubjectInfo{IDFrom: "user_id"},
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
		{
			uc: "execution with not active session",
			authenticator: &genericAuthenticator{
				id: "auth3",
				e: endpoint.Endpoint{
					URL:    srv.URL,
					Method: http.MethodGet,
					Headers: map[string]string{
						"Accept": "application/json",
					},
				},
				sf:                  &SubjectInfo{IDFrom: "user_id"},
				ttl:                 5 * time.Second,
				sessionLifespanConf: &SessionLifespanConfig{ActiveField: "active"},
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
				responseContent = []byte(`{ "user_id": "barbar", "active": false }`)
				responseContentType = "application/json"
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.Contains(t, err.Error(), "not active")

				var identifier HandlerIdentifier
				require.True(t, errors.As(err, &identifier))
				assert.Equal(t, "auth3", identifier.HandlerID())
			},
		},
		{
			uc: "execution with error while parsing session lifespan",
			authenticator: &genericAuthenticator{
				id: "auth3",
				e: endpoint.Endpoint{
					URL:    srv.URL,
					Method: http.MethodGet,
					Headers: map[string]string{
						"Accept": "application/json",
					},
				},
				sf:                  &SubjectInfo{IDFrom: "user_id"},
				ttl:                 5 * time.Second,
				sessionLifespanConf: &SessionLifespanConfig{IssuedAtField: "iat"},
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
				responseContent = []byte(`{ "user_id": "barbar", "iat": "2006-01-02T15:04:05.999999Z07" }`)
				responseContentType = "application/json"
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed parsing issued_at")

				var identifier HandlerIdentifier
				require.True(t, errors.As(err, &identifier))
				assert.Equal(t, "auth3", identifier.HandlerID())
			},
		},
		{
			uc: "execution with session lifespan ttl limiting the configured ttl",
			authenticator: &genericAuthenticator{
				e: endpoint.Endpoint{
					URL:    srv.URL,
					Method: http.MethodGet,
					Headers: map[string]string{
						"Accept": "application/json",
					},
				},
				sf:                  &SubjectInfo{IDFrom: "user_id"},
				ttl:                 30 * time.Second,
				sessionLifespanConf: &SessionLifespanConfig{NotAfterField: "exp"},
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.MockContext,
				cch *mocks.MockCache,
				ads *mockAuthDataGetter,
				auth *genericAuthenticator,
			) {
				t.Helper()

				exp := strconv.FormatInt(time.Now().Add(15*time.Second).Unix(), 10)
				cacheKey := auth.calculateCacheKey("session_token")

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: "session_token"}, nil)
				cch.On("Get", cacheKey).Return(nil)
				cch.On("Set", cacheKey, []byte(`{ "user_id": "barbar", "exp": `+exp+` }`), 5*time.Second)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				exp := strconv.FormatInt(time.Now().Add(15*time.Second).Unix(), 10)

				checkRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, http.MethodGet, req.Method)
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
					assert.Equal(t, "session_token", req.Header.Get("Dummy"))
				}

				responseCode = http.StatusOK
				responseContent = []byte(`{ "user_id": "barbar", "exp": ` + exp + ` }`)
				responseContentType = "application/json"
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				require.NoError(t, err)

				require.NotNil(t, sub)
				assert.Equal(t, "barbar", sub.ID)
				assert.Len(t, sub.Attributes, 2)
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

func TestGenericAuthenticatorGetCacheTTL(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc              string
		authenticator   *genericAuthenticator
		sessionLifespan *SessionLifespan
		assert          func(t *testing.T, ttl time.Duration)
	}{
		{
			uc:            "cache disabled",
			authenticator: &genericAuthenticator{},
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, time.Duration(0), ttl)
			},
		},
		{
			uc:            "cache enabled, session lifespan not available",
			authenticator: &genericAuthenticator{ttl: 5 * time.Minute},
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, 5*time.Minute, ttl)
			},
		},
		{
			uc:              "cache enabled, session lifespan available, but not_after is not available",
			authenticator:   &genericAuthenticator{ttl: 5 * time.Minute},
			sessionLifespan: &SessionLifespan{},
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, 5*time.Minute, ttl)
			},
		},
		{
			uc: "cache enabled, session lifespan available with not_after set to a future date exceeding configured" +
				" ttl",
			authenticator:   &genericAuthenticator{ttl: 5 * time.Minute},
			sessionLifespan: &SessionLifespan{exp: time.Now().Add(24 * time.Hour)},
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, 5*time.Minute, ttl)
			},
		},
		{
			uc: "cache enabled, session lifespan available with not_after set to a date so that the configured ttl " +
				"would exceed the lifespan",
			authenticator:   &genericAuthenticator{ttl: 5 * time.Minute},
			sessionLifespan: &SessionLifespan{exp: time.Now().Add(30 * time.Second)},
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, 20*time.Second, ttl) // leeway of 10 sec considered
			},
		},
		{
			uc:              "cache enabled, session lifespan available with not_after set to a date which disables ttl",
			authenticator:   &genericAuthenticator{ttl: 5 * time.Minute},
			sessionLifespan: &SessionLifespan{exp: time.Now().Add(5 * time.Second)},
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, 0*time.Second, ttl)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			ttl := tc.authenticator.getCacheTTL(tc.sessionLifespan)

			// THEN
			tc.assert(t, ttl)
		})
	}
}
