package decision

import (
	"crypto/rand"
	"crypto/rsa"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/requestcontext"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/keystore"
	mocks2 "github.com/dadrus/heimdall/internal/rules/mocks"
	mocks4 "github.com/dadrus/heimdall/internal/rules/rule/mocks"
)

// nolint: gocognit, cyclop, maintidx
func TestHandleDecisionEndpointRequest(t *testing.T) {
	t.Parallel()

	const rsa2048 = 2048

	privateKey, err := rsa.GenerateKey(rand.Reader, rsa2048)
	require.NoError(t, err)

	ks, err := keystore.NewKeyStoreFromKey(privateKey)
	require.NoError(t, err)

	for _, tc := range []struct {
		uc             string
		serviceConf    config.ServiceConfig
		createRequest  func(t *testing.T) *http.Request
		configureMocks func(t *testing.T, repository *mocks2.MockRepository, rule *mocks4.MockRule)
		assertResponse func(t *testing.T, err error, response *http.Response)
	}{
		{
			uc: "no rules configured",
			createRequest: func(t *testing.T) *http.Request {
				t.Helper()

				return httptest.NewRequest("GET", "/decisions", nil)
			},
			configureMocks: func(t *testing.T, repository *mocks2.MockRepository, rule *mocks4.MockRule) {
				t.Helper()

				repository.On("FindRule", mock.Anything).Return(nil, heimdall.ErrNoRuleFound)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusNotFound, response.StatusCode)

				data, err := ioutil.ReadAll(response.Body)
				require.NoError(t, err)
				assert.Len(t, data, 0)
			},
		},
		{
			uc: "rule doesn't match method",
			createRequest: func(t *testing.T) *http.Request {
				t.Helper()

				return httptest.NewRequest("POST", "/decisions", nil)
			},
			configureMocks: func(t *testing.T, repository *mocks2.MockRepository, rule *mocks4.MockRule) {
				t.Helper()

				rule.On("MatchesMethod", "POST").Return(false)

				repository.On("FindRule", mock.Anything).Return(rule, nil)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusMethodNotAllowed, response.StatusCode)

				data, err := ioutil.ReadAll(response.Body)
				require.NoError(t, err)
				assert.Len(t, data, 0)
			},
		},
		{
			uc: "rule execution fails with authentication error",
			createRequest: func(t *testing.T) *http.Request {
				t.Helper()

				return httptest.NewRequest("POST", "/decisions", nil)
			},
			configureMocks: func(t *testing.T, repository *mocks2.MockRepository, rule *mocks4.MockRule) {
				t.Helper()

				rule.On("MatchesMethod", "POST").Return(true)
				rule.On("Execute", mock.Anything).Return(heimdall.ErrAuthentication)

				repository.On("FindRule", mock.Anything).Return(rule, nil)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusUnauthorized, response.StatusCode)

				data, err := ioutil.ReadAll(response.Body)
				require.NoError(t, err)
				assert.Len(t, data, 0)
			},
		},
		{
			uc: "rule execution fails with pipeline authorization error",
			createRequest: func(t *testing.T) *http.Request {
				t.Helper()

				return httptest.NewRequest("POST", "/decisions", nil)
			},
			configureMocks: func(t *testing.T, repository *mocks2.MockRepository, rule *mocks4.MockRule) {
				t.Helper()

				rule.On("MatchesMethod", "POST").Return(true)
				rule.On("Execute", mock.MatchedBy(func(ctx *requestcontext.RequestContext) bool {
					ctx.SetPipelineError(heimdall.ErrAuthorization)

					return true
				})).Return(nil)

				repository.On("FindRule", mock.Anything).Return(rule, nil)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusForbidden, response.StatusCode)

				data, err := ioutil.ReadAll(response.Body)
				require.NoError(t, err)
				assert.Len(t, data, 0)
			},
		},
		{
			uc: "successful rule execution - request method, path and hostname " +
				"are taken from the real request (trusted proxy not configured)",
			createRequest: func(t *testing.T) *http.Request {
				t.Helper()

				return httptest.NewRequest(
					"POST",
					"http://heimdall.test.local/decisions/foobar",
					nil)
			},
			configureMocks: func(t *testing.T, repository *mocks2.MockRepository, rule *mocks4.MockRule) {
				t.Helper()

				rule.On("MatchesMethod", "POST").Return(true)
				rule.On("Execute", mock.MatchedBy(func(ctx *requestcontext.RequestContext) bool {
					ctx.AddHeaderForUpstream("X-Foo-Bar", "baz")
					ctx.AddCookieForUpstream("X-Bar-Foo", "zab")

					return true
				})).Return(nil)

				repository.On("FindRule", mock.MatchedBy(func(reqURL *url.URL) bool {
					return reqURL.Scheme == "http" && reqURL.Host == "heimdall.test.local" && reqURL.Path == "foobar"
				})).Return(rule, nil)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusAccepted, response.StatusCode)

				data, err := ioutil.ReadAll(response.Body)
				require.NoError(t, err)
				assert.Len(t, data, 0)

				headerVal := response.Header.Get("X-Foo-Bar")
				assert.Equal(t, headerVal, "baz")

				cookies := response.Cookies()
				require.Len(t, cookies, 1)
				assert.Equal(t, "X-Bar-Foo", cookies[0].Name)
				assert.Equal(t, "zab", cookies[0].Value)
			},
		},
		{
			uc: "successful rule execution - request method, path and hostname " +
				"all are taken from the headers (trusted proxy not configured)",
			createRequest: func(t *testing.T) *http.Request {
				t.Helper()

				req := httptest.NewRequest(
					"POST",
					"http://heimdall.test.local/decisions/foobar",
					nil)

				req.Header.Set("X-Forwarded-Proto", "https")
				req.Header.Set("X-Forwarded-Host", "test.com")
				req.Header.Set("X-Forwarded-Uri", "bar")
				req.Header.Set("X-Forwarded-Method", "GET")

				return req
			},
			configureMocks: func(t *testing.T, repository *mocks2.MockRepository, rule *mocks4.MockRule) {
				t.Helper()

				rule.On("MatchesMethod", "GET").Return(true)
				rule.On("Execute", mock.MatchedBy(func(ctx *requestcontext.RequestContext) bool {
					ctx.AddHeaderForUpstream("X-Foo-Bar", "baz")
					ctx.AddCookieForUpstream("X-Bar-Foo", "zab")

					return true
				})).Return(nil)

				repository.On("FindRule", mock.MatchedBy(func(reqURL *url.URL) bool {
					return reqURL.Scheme == "https" && reqURL.Host == "test.com" && reqURL.Path == "bar"
				})).Return(rule, nil)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusAccepted, response.StatusCode)

				data, err := ioutil.ReadAll(response.Body)
				require.NoError(t, err)
				assert.Len(t, data, 0)

				headerVal := response.Header.Get("X-Foo-Bar")
				assert.Equal(t, headerVal, "baz")

				cookies := response.Cookies()
				require.Len(t, cookies, 1)
				assert.Equal(t, "X-Bar-Foo", cookies[0].Name)
				assert.Equal(t, "zab", cookies[0].Value)
			},
		},
		{
			uc: "successful rule execution - request method, path and hostname " +
				"all are not taken from the headers (trusted proxy configured and does not match host)",
			serviceConf: config.ServiceConfig{TrustedProxies: &[]string{"111.111.111.111"}},
			createRequest: func(t *testing.T) *http.Request {
				t.Helper()

				req := httptest.NewRequest(
					"POST",
					"http://heimdall.test.local/decisions/foobar",
					nil)

				req.Header.Set("X-Forwarded-Proto", "https")
				req.Header.Set("X-Forwarded-Host", "test.com")
				req.Header.Set("X-Forwarded-Uri", "bar")
				req.Header.Set("X-Forwarded-Method", "GET")

				return req
			},
			configureMocks: func(t *testing.T, repository *mocks2.MockRepository, rule *mocks4.MockRule) {
				t.Helper()

				rule.On("MatchesMethod", "POST").Return(true)
				rule.On("Execute", mock.MatchedBy(func(ctx *requestcontext.RequestContext) bool {
					ctx.AddHeaderForUpstream("X-Foo-Bar", "baz")
					ctx.AddCookieForUpstream("X-Bar-Foo", "zab")

					return true
				})).Return(nil)

				repository.On("FindRule", mock.MatchedBy(func(reqURL *url.URL) bool {
					return reqURL.Scheme == "http" && reqURL.Host == "heimdall.test.local" && reqURL.Path == "foobar"
				})).Return(rule, nil)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusAccepted, response.StatusCode)

				data, err := ioutil.ReadAll(response.Body)
				require.NoError(t, err)
				assert.Len(t, data, 0)

				headerVal := response.Header.Get("X-Foo-Bar")
				assert.Equal(t, headerVal, "baz")

				cookies := response.Cookies()
				require.Len(t, cookies, 1)
				assert.Equal(t, "X-Bar-Foo", cookies[0].Name)
				assert.Equal(t, "zab", cookies[0].Value)
			},
		},
		{
			uc: "successful rule execution - only request method is sent via header" +
				"(trusted proxy configured and matches host)",
			serviceConf: config.ServiceConfig{TrustedProxies: &[]string{"0.0.0.0/0"}},
			createRequest: func(t *testing.T) *http.Request {
				t.Helper()

				req := httptest.NewRequest(
					"POST",
					"http://heimdall.test.local/decisions/foobar",
					nil)

				req.Header.Set("X-Forwarded-Method", "GET")

				return req
			},
			configureMocks: func(t *testing.T, repository *mocks2.MockRepository, rule *mocks4.MockRule) {
				t.Helper()

				rule.On("MatchesMethod", "GET").Return(true)
				rule.On("Execute", mock.Anything).Return(nil)

				repository.On("FindRule", mock.MatchedBy(func(reqURL *url.URL) bool {
					return reqURL.Scheme == "http" && reqURL.Host == "heimdall.test.local" && reqURL.Path == "foobar"
				})).Return(rule, nil)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusAccepted, response.StatusCode)
			},
		},
		{
			uc: "successful rule execution - only host is sent via header" +
				"(trusted proxy configured and matches host)",
			serviceConf: config.ServiceConfig{TrustedProxies: &[]string{"0.0.0.0/0"}},
			createRequest: func(t *testing.T) *http.Request {
				t.Helper()

				req := httptest.NewRequest(
					"POST",
					"http://heimdall.test.local/decisions/foobar",
					nil)

				req.Header.Set("X-Forwarded-Host", "test.com")

				return req
			},
			configureMocks: func(t *testing.T, repository *mocks2.MockRepository, rule *mocks4.MockRule) {
				t.Helper()

				rule.On("MatchesMethod", "POST").Return(true)
				rule.On("Execute", mock.Anything).Return(nil)

				repository.On("FindRule", mock.MatchedBy(func(reqURL *url.URL) bool {
					return reqURL.Scheme == "http" && reqURL.Host == "test.com" && reqURL.Path == "foobar"
				})).Return(rule, nil)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusAccepted, response.StatusCode)
			},
		},
		{
			uc: "successful rule execution - only path is sent via header" +
				"(trusted proxy configured and matches host)",
			serviceConf: config.ServiceConfig{TrustedProxies: &[]string{"0.0.0.0/0"}},
			createRequest: func(t *testing.T) *http.Request {
				t.Helper()

				req := httptest.NewRequest(
					"POST",
					"http://heimdall.test.local/decisions/foobar",
					nil)

				req.Header.Set("X-Forwarded-Uri", "bar")

				return req
			},
			configureMocks: func(t *testing.T, repository *mocks2.MockRepository, rule *mocks4.MockRule) {
				t.Helper()

				rule.On("MatchesMethod", "POST").Return(true)
				rule.On("Execute", mock.Anything).Return(nil)

				repository.On("FindRule", mock.MatchedBy(func(reqURL *url.URL) bool {
					return reqURL.Scheme == "http" && reqURL.Host == "heimdall.test.local" && reqURL.Path == "bar"
				})).Return(rule, nil)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusAccepted, response.StatusCode)
			},
		},
		{
			uc: "successful rule execution - only scheme is sent via header" +
				"(trusted proxy configured and matches host)",
			serviceConf: config.ServiceConfig{TrustedProxies: &[]string{"0.0.0.0/0"}},
			createRequest: func(t *testing.T) *http.Request {
				t.Helper()

				req := httptest.NewRequest(
					"POST",
					"http://heimdall.test.local/decisions/foobar",
					nil)

				req.Header.Set("X-Forwarded-Proto", "https")

				return req
			},
			configureMocks: func(t *testing.T, repository *mocks2.MockRepository, rule *mocks4.MockRule) {
				t.Helper()

				rule.On("MatchesMethod", "POST").Return(true)
				rule.On("Execute", mock.Anything).Return(nil)

				repository.On("FindRule", mock.MatchedBy(func(reqURL *url.URL) bool {
					return reqURL.Scheme == "https" && reqURL.Host == "heimdall.test.local" && reqURL.Path == "foobar"
				})).Return(rule, nil)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusAccepted, response.StatusCode)
			},
		},
		{
			uc: "successful rule execution - scheme, host, path and method sent via header" +
				"(trusted proxy configured and matches host)",
			serviceConf: config.ServiceConfig{TrustedProxies: &[]string{"0.0.0.0/0"}},
			createRequest: func(t *testing.T) *http.Request {
				t.Helper()

				req := httptest.NewRequest(
					"POST",
					"http://heimdall.test.local/decisions/foobar",
					nil)

				req.Header.Set("X-Forwarded-Proto", "https")
				req.Header.Set("X-Forwarded-Host", "test.com")
				req.Header.Set("X-Forwarded-Uri", "bar")
				req.Header.Set("X-Forwarded-Method", "PATCH")

				return req
			},
			configureMocks: func(t *testing.T, repository *mocks2.MockRepository, rule *mocks4.MockRule) {
				t.Helper()

				rule.On("MatchesMethod", "PATCH").Return(true)
				rule.On("Execute", mock.Anything).Return(nil)

				repository.On("FindRule", mock.MatchedBy(func(reqURL *url.URL) bool {
					return reqURL.Scheme == "https" && reqURL.Host == "test.com" && reqURL.Path == "bar"
				})).Return(rule, nil)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusAccepted, response.StatusCode)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			conf := config.Configuration{Serve: config.ServeConfig{Decision: tc.serviceConf}}
			cch := &mocks.MockCache{}
			repo := &mocks2.MockRepository{}
			rule := &mocks4.MockRule{}
			logger := log.Logger

			tc.configureMocks(t, repo, rule)

			app := newFiberApp(conf, cch)
			defer app.Shutdown() // nolint: errcheck

			_, err := newHandler(handlerParams{
				App:             app,
				RulesRepository: repo,
				Logger:          logger,
				KeyStore:        ks,
			})
			require.NoError(t, err)

			// WHEN
			resp, err := app.Test(tc.createRequest(t), -1)

			// THEN
			if err == nil {
				defer resp.Body.Close()
			}

			tc.assertResponse(t, err, resp)
			repo.AssertExpectations(t)
			rule.AssertExpectations(t)
		})
	}
}
