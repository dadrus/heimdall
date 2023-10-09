package finalizers

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
	mocks2 "github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestNewClientCredentialsFinalizer(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		id     string
		config []byte
		assert func(t *testing.T, err error, finalizer *oauth2ClientCredentialsFinalizer)
	}{
		{
			uc: "without configuration",
			assert: func(t *testing.T, err error, _ *oauth2ClientCredentialsFinalizer) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed validating")
				assert.Contains(t, err.Error(), "token_url")
				assert.Contains(t, err.Error(), "client_id")
				assert.Contains(t, err.Error(), "client_secret")
			},
		},
		{
			uc:     "with empty configuration",
			config: []byte(``),
			assert: func(t *testing.T, err error, _ *oauth2ClientCredentialsFinalizer) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed validating")
				assert.Contains(t, err.Error(), "token_url")
				assert.Contains(t, err.Error(), "client_id")
				assert.Contains(t, err.Error(), "client_secret")
			},
		},
		{
			uc: "with unsupported attributes",
			config: []byte(`
token_url: https://foo.bar
foo: bar
`),
			assert: func(t *testing.T, err error, _ *oauth2ClientCredentialsFinalizer) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "invalid keys")
			},
		},
		{
			uc: "with minimal valid config",
			id: "minimal",
			config: []byte(`
token_url: https://foo.bar
client_id: foo
client_secret: bar
`),
			assert: func(t *testing.T, err error, finalizer *oauth2ClientCredentialsFinalizer) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, finalizer)

				assert.Equal(t, "minimal", finalizer.ID())
				assert.Equal(t, "https://foo.bar", finalizer.tokenURL)
				assert.Equal(t, "foo", finalizer.clientID)
				assert.Equal(t, "bar", finalizer.clientSecret)
				assert.Equal(t, "Authorization", finalizer.headerName)
				assert.Equal(t, "Bearer", finalizer.headerScheme)
				assert.Nil(t, finalizer.ttl)
				assert.Empty(t, finalizer.scopes)
				assert.False(t, finalizer.ContinueOnError())
			},
		},
		{
			uc: "with full valid config",
			id: "full",
			config: []byte(`
token_url: https://foo.bar
client_id: foo
client_secret: bar
cache_ttl: 11s
scopes:
  - foo
  - baz
header:
  name: "X-My-Header"
  scheme: Foo
`),
			assert: func(t *testing.T, err error, finalizer *oauth2ClientCredentialsFinalizer) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, finalizer)

				assert.Equal(t, "full", finalizer.ID())
				assert.Equal(t, "https://foo.bar", finalizer.tokenURL)
				assert.Equal(t, "foo", finalizer.clientID)
				assert.Equal(t, "bar", finalizer.clientSecret)
				assert.Equal(t, "X-My-Header", finalizer.headerName)
				assert.Equal(t, "Foo", finalizer.headerScheme)
				assert.Equal(t, 11*time.Second, *finalizer.ttl)
				assert.Len(t, finalizer.scopes, 2)
				assert.Contains(t, finalizer.scopes, "foo")
				assert.Contains(t, finalizer.scopes, "baz")
				assert.False(t, finalizer.ContinueOnError())
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			finalizer, err := newOAuth2ClientCredentialsFinalizer(tc.id, conf)

			// THEN
			tc.assert(t, err, finalizer)
		})
	}
}

func TestCreateClientCredentialsFinalizerFromPrototype(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc              string
		id              string
		prototypeConfig []byte
		config          []byte
		assert          func(t *testing.T, err error, prototype *oauth2ClientCredentialsFinalizer, configured *oauth2ClientCredentialsFinalizer)
	}{
		{
			uc: "no new configuration provided",
			id: "1",
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
  scheme: Foo
`),
			assert: func(t *testing.T, err error, prototype *oauth2ClientCredentialsFinalizer, configured *oauth2ClientCredentialsFinalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
			},
		},
		{
			uc: "empty configuration provided",
			id: "2",
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
  scheme: Foo
`),
			config: []byte(``),
			assert: func(t *testing.T, err error, prototype *oauth2ClientCredentialsFinalizer, configured *oauth2ClientCredentialsFinalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
				assert.Equal(t, "2", configured.ID())
			},
		},
		{
			uc: "scopes reconfigured",
			id: "3",
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
				assert.Equal(t, "https://foo.bar", prototype.tokenURL)
				assert.Equal(t, prototype.tokenURL, configured.tokenURL)
				assert.Equal(t, "foo", prototype.clientID)
				assert.Equal(t, prototype.clientID, configured.clientID)
				assert.Equal(t, "bar", prototype.clientSecret)
				assert.Equal(t, prototype.clientSecret, configured.clientSecret)
				assert.Equal(t, 11*time.Second, *prototype.ttl)
				assert.Equal(t, prototype.ttl, configured.ttl)
				assert.Equal(t, "Authorization", prototype.headerName)
				assert.Equal(t, prototype.headerName, configured.headerName)
				assert.Equal(t, "Bearer", prototype.headerScheme)
				assert.Equal(t, prototype.headerScheme, configured.headerScheme)
				assert.Empty(t, prototype.scopes)
				assert.Len(t, configured.scopes, 2)
				assert.Contains(t, configured.scopes, "foo")
				assert.Contains(t, configured.scopes, "baz")
			},
		},
		{
			uc: "ttl reconfigured",
			id: "3",
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
				assert.Equal(t, "https://foo.bar", prototype.tokenURL)
				assert.Equal(t, prototype.tokenURL, configured.tokenURL)
				assert.Equal(t, "foo", prototype.clientID)
				assert.Equal(t, prototype.clientID, configured.clientID)
				assert.Equal(t, "bar", prototype.clientSecret)
				assert.Equal(t, prototype.clientSecret, configured.clientSecret)
				assert.Equal(t, 11*time.Second, *prototype.ttl)
				assert.Equal(t, 12*time.Second, *configured.ttl)
				assert.Equal(t, "Authorization", prototype.headerName)
				assert.Equal(t, prototype.headerName, configured.headerName)
				assert.Equal(t, "Bearer", prototype.headerScheme)
				assert.Equal(t, prototype.headerScheme, configured.headerScheme)
				assert.Empty(t, prototype.scopes)
				assert.Equal(t, prototype.scopes, configured.scopes)
			},
		},
		{
			uc: "unsupported attributes while reconfiguring",
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
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to unmarshal")

				require.NotNil(t, prototype)
				require.Nil(t, configured)
			},
		},
		{
			uc: "header name reconfigured",
			id: "3",
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
				assert.Equal(t, "https://foo.bar", prototype.tokenURL)
				assert.Equal(t, prototype.tokenURL, configured.tokenURL)
				assert.Equal(t, "foo", prototype.clientID)
				assert.Equal(t, prototype.clientID, configured.clientID)
				assert.Equal(t, "bar", prototype.clientSecret)
				assert.Equal(t, prototype.clientSecret, configured.clientSecret)
				assert.Equal(t, 11*time.Second, *prototype.ttl)
				assert.Equal(t, prototype.ttl, configured.ttl)
				assert.Equal(t, "Authorization", prototype.headerName)
				assert.Equal(t, "X-Foo-Bar", configured.headerName)
				assert.Equal(t, "Bearer", prototype.headerScheme)
				assert.Empty(t, configured.headerScheme)
				assert.Empty(t, prototype.scopes)
				assert.Equal(t, prototype.scopes, configured.scopes)
			},
		},
		{
			uc: "header name and scheme reconfigured",
			id: "3",
			prototypeConfig: []byte(`
token_url: https://foo.bar
client_id: foo
client_secret: bar
cache_ttl: 11s
`),
			config: []byte(`
header:
  name: X-Foo-Bar
  scheme: Foo
`),
			assert: func(t *testing.T, err error, prototype *oauth2ClientCredentialsFinalizer, configured *oauth2ClientCredentialsFinalizer) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.ID(), configured.ID())
				assert.Equal(t, "https://foo.bar", prototype.tokenURL)
				assert.Equal(t, prototype.tokenURL, configured.tokenURL)
				assert.Equal(t, "foo", prototype.clientID)
				assert.Equal(t, prototype.clientID, configured.clientID)
				assert.Equal(t, "bar", prototype.clientSecret)
				assert.Equal(t, prototype.clientSecret, configured.clientSecret)
				assert.Equal(t, 11*time.Second, *prototype.ttl)
				assert.Equal(t, prototype.ttl, configured.ttl)
				assert.Equal(t, "Authorization", prototype.headerName)
				assert.Equal(t, "X-Foo-Bar", configured.headerName)
				assert.Equal(t, "Bearer", prototype.headerScheme)
				assert.Equal(t, "Foo", configured.headerScheme)
				assert.Empty(t, prototype.scopes)
				assert.Equal(t, prototype.scopes, configured.scopes)
			},
		},
		{
			uc: "only header scheme reconfigured",
			id: "3",
			prototypeConfig: []byte(`
token_url: https://foo.bar
client_id: foo
client_secret: bar
cache_ttl: 11s
`),
			config: []byte(`
header:
  scheme: Foo
`),
			assert: func(t *testing.T, err error, prototype *oauth2ClientCredentialsFinalizer, configured *oauth2ClientCredentialsFinalizer) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed validating")
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			pc, err := testsupport.DecodeTestConfig(tc.prototypeConfig)
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			prototype, err := newOAuth2ClientCredentialsFinalizer(tc.id, pc)
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
		response struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			ExpiresIn   int64  `json:"expires_in,omitempty"`
		}

		RequestAsserter func(t *testing.T, req *http.Request)
		ResponseBuilder func(t *testing.T) any
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

		resp := buildResponse(t)

		rawResp, err := json.MarshalContext(req.Context(), resp)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(rawResp)))

		_, err = w.Write(rawResp)
		assert.NoError(t, err)
	}))
	defer srv.Close()

	for _, tc := range []struct {
		uc             string
		finalizer      *oauth2ClientCredentialsFinalizer
		configureMocks func(t *testing.T, ctx *mocks.ContextMock, cch *mocks2.CacheMock)
		assertRequest  RequestAsserter
		buildResponse  ResponseBuilder
		assert         func(t *testing.T, err error, tokenEndpointCalled bool)
	}{
		{
			uc: "reusing response from cache",
			finalizer: &oauth2ClientCredentialsFinalizer{
				id:           "test",
				headerName:   "Authorization",
				headerScheme: "Bearer",
			},
			configureMocks: func(t *testing.T, ctx *mocks.ContextMock, cch *mocks2.CacheMock) {
				t.Helper()

				cch.EXPECT().Get(mock.Anything).Return(&tokenEndpointResponse{AccessToken: "foobar"})
				ctx.EXPECT().AddHeaderForUpstream("Authorization", "Bearer foobar")
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool) {
				t.Helper()

				require.NoError(t, err)
				assert.False(t, tokenEndpointCalled)
			},
		},
		{
			uc: "cache entry of wrong type and no ttl in issued token",
			finalizer: &oauth2ClientCredentialsFinalizer{
				id:           "test",
				headerName:   "Authorization",
				headerScheme: "Bearer",
				tokenURL:     srv.URL,
				clientID:     "foo",
				clientSecret: "bar",
			},
			configureMocks: func(t *testing.T, ctx *mocks.ContextMock, cch *mocks2.CacheMock) {
				t.Helper()

				cch.EXPECT().Get(mock.Anything).Return("foobar")
				cch.EXPECT().Delete(mock.Anything)
				ctx.EXPECT().AddHeaderForUpstream("Authorization", "Bearer barfoo")
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
			buildResponse: func(t *testing.T) any {
				t.Helper()

				return &response{
					AccessToken: "barfoo",
					TokenType:   "Foo",
				}
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, tokenEndpointCalled)
			},
		},
		{
			uc: "ttl not configured, no cache entry and token has expires_in claim",
			finalizer: &oauth2ClientCredentialsFinalizer{
				id:           "test",
				headerName:   "Authorization",
				headerScheme: "Bar",
				tokenURL:     srv.URL,
				clientID:     "bar",
				clientSecret: "foo",
			},
			configureMocks: func(t *testing.T, ctx *mocks.ContextMock, cch *mocks2.CacheMock) {
				t.Helper()

				expIn := int64((5 * time.Minute).Seconds())

				cch.EXPECT().Get(mock.Anything).Return(nil)
				cch.EXPECT().Set(mock.Anything,
					&tokenEndpointResponse{
						AccessToken: "barfoo",
						TokenType:   "Foo",
						ExpiresIn:   &expIn,
					},
					5*time.Minute-5*time.Second,
				).Return()
				ctx.EXPECT().AddHeaderForUpstream("Authorization", "Bar barfoo").Return()
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
			buildResponse: func(t *testing.T) any {
				t.Helper()

				expiresIn := int64((5 * time.Minute).Seconds())

				return &response{
					AccessToken: "barfoo",
					TokenType:   "Foo",
					ExpiresIn:   expiresIn,
				}
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, tokenEndpointCalled)
			},
		},
		{
			uc: "error while unmarshalling token",
			finalizer: &oauth2ClientCredentialsFinalizer{
				id:           "test",
				tokenURL:     srv.URL,
				clientID:     "bar",
				clientSecret: "foo",
			},
			configureMocks: func(t *testing.T, ctx *mocks.ContextMock, cch *mocks2.CacheMock) {
				t.Helper()

				cch.EXPECT().Get(mock.Anything).Return(nil)
			},
			assertRequest: func(t *testing.T, req *http.Request) { t.Helper() },
			buildResponse: func(t *testing.T) any {
				t.Helper()

				return "foo"
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool) {
				t.Helper()

				assert.True(t, tokenEndpointCalled)
				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
			},
		},
		{
			uc: "error while sending request",
			finalizer: &oauth2ClientCredentialsFinalizer{
				id:           "test",
				tokenURL:     "http://127.0.0.1:11111",
				clientID:     "bar",
				clientSecret: "foo",
			},
			configureMocks: func(t *testing.T, ctx *mocks.ContextMock, cch *mocks2.CacheMock) {
				t.Helper()

				cch.EXPECT().Get(mock.Anything).Return(nil)
			},
			assertRequest: func(t *testing.T, req *http.Request) { t.Helper() },
			buildResponse: func(t *testing.T) any {
				t.Helper()

				return "foo"
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool) {
				t.Helper()

				assert.False(t, tokenEndpointCalled)
				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrCommunication)
			},
		},
		{
			uc: "full configuration, no cache hit and token has expires_in claim",
			finalizer: &oauth2ClientCredentialsFinalizer{
				id:           "test",
				headerName:   "X-My-Header",
				headerScheme: "Foo",
				tokenURL:     srv.URL,
				clientID:     "bar",
				clientSecret: "foo",
				ttl: func() *time.Duration {
					ttl := 3 * time.Minute

					return &ttl
				}(),
				scopes: []string{"baz", "zab"},
			},
			configureMocks: func(t *testing.T, ctx *mocks.ContextMock, cch *mocks2.CacheMock) {
				t.Helper()

				expIn := int64((5 * time.Minute).Seconds())

				cch.EXPECT().Get(mock.Anything).Return(nil)
				cch.EXPECT().Set(mock.Anything,
					&tokenEndpointResponse{
						AccessToken: "foobar",
						TokenType:   "Foo",
						ExpiresIn:   &expIn,
					},
					3*time.Minute,
				).Return()
				ctx.EXPECT().AddHeaderForUpstream("X-My-Header", "Foo foobar").Return()
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
			buildResponse: func(t *testing.T) any {
				t.Helper()

				expiresIn := int64((5 * time.Minute).Seconds())

				return &response{
					AccessToken: "foobar",
					TokenType:   "Foo",
					ExpiresIn:   expiresIn,
				}
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, tokenEndpointCalled)
			},
		},
		{
			uc: "disabled cache",
			finalizer: &oauth2ClientCredentialsFinalizer{
				id:           "test",
				headerName:   "X-My-Header",
				headerScheme: "Foo",
				tokenURL:     srv.URL,
				clientID:     "bar",
				clientSecret: "foo",
				ttl: func() *time.Duration {
					ttl := 0 * time.Second

					return &ttl
				}(),
				scopes: []string{"baz", "zab"},
			},
			configureMocks: func(t *testing.T, ctx *mocks.ContextMock, cch *mocks2.CacheMock) {
				t.Helper()

				ctx.EXPECT().AddHeaderForUpstream("X-My-Header", "Foo foobar").Return()
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
			buildResponse: func(t *testing.T) any {
				t.Helper()

				expiresIn := int64((5 * time.Minute).Seconds())

				return &response{
					AccessToken: "foobar",
					TokenType:   "Foo",
					ExpiresIn:   expiresIn,
				}
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, tokenEndpointCalled)
			},
		},
		{
			uc: "custom cache ttl and no expires_in in token",
			finalizer: &oauth2ClientCredentialsFinalizer{
				id:           "test",
				headerName:   "X-My-Header",
				headerScheme: "Foo",
				tokenURL:     srv.URL,
				clientID:     "bar",
				clientSecret: "foo",
				ttl: func() *time.Duration {
					ttl := 3 * time.Minute

					return &ttl
				}(),
				scopes: []string{"baz", "zab"},
			},
			configureMocks: func(t *testing.T, ctx *mocks.ContextMock, cch *mocks2.CacheMock) {
				t.Helper()

				cch.EXPECT().Get(mock.Anything).Return(nil)
				cch.EXPECT().Set(mock.Anything,
					&tokenEndpointResponse{
						AccessToken: "foobar",
						TokenType:   "Foo",
					},
					3*time.Minute,
				).Return()
				ctx.EXPECT().AddHeaderForUpstream("X-My-Header", "Foo foobar").Return()
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
			buildResponse: func(t *testing.T) any {
				t.Helper()

				return &response{
					AccessToken: "foobar",
					TokenType:   "Foo",
				}
			},
			assert: func(t *testing.T, err error, tokenEndpointCalled bool) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, tokenEndpointCalled)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			endpointCalled = false
			configureMocks := x.IfThenElse(tc.configureMocks != nil,
				tc.configureMocks,
				func(t *testing.T, _ *mocks.ContextMock, _ *mocks2.CacheMock) { t.Helper() },
			)

			cch := mocks2.NewCacheMock(t)
			ctx := mocks.NewContextMock(t)

			ctx.EXPECT().AppContext().Return(cache.WithContext(context.Background(), cch))
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
