package proxy

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

func TestHandleProxyEndpointRequest(t *testing.T) {
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

				return httptest.NewRequest("GET", "http://heimdal.test.local/foobar", nil)
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

				return httptest.NewRequest("POST", "http://heimdal.test.local/foobar", nil)
			},
			configureMocks: func(t *testing.T, repository *mocks2.MockRepository, rule *mocks4.MockRule) {
				t.Helper()

				rule.On("MatchesMethod", "POST").Return(false)
				rule.On("ID").Return("test")
				rule.On("SrcID").Return("test")

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
			uc: "rule execution fails due to not configured upstream url",
			createRequest: func(t *testing.T) *http.Request {
				t.Helper()

				return httptest.NewRequest("POST", "http://heimdal.test.local/foobar", nil)
			},
			configureMocks: func(t *testing.T, repository *mocks2.MockRepository, rule *mocks4.MockRule) {
				t.Helper()

				rule.On("ID").Return("test")
				rule.On("SrcID").Return("test")
				rule.On("UpstreamURL", mock.MatchedBy(
					func(URL *url.URL) bool { return URL.String() == "http://heimdal.test.local/foobar" }),
				).Return(&url.URL{Scheme: "http", Host: "heimdal.test.local", Path: "/foobar"})
				rule.On("MatchesMethod", "POST").Return(true)

				repository.On("FindRule", mock.Anything).Return(rule, nil)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusInternalServerError, response.StatusCode)

				data, err := ioutil.ReadAll(response.Body)
				require.NoError(t, err)
				assert.Len(t, data, 0)
			},
		},
		{
			uc: "rule execution fails with authentication error",
			createRequest: func(t *testing.T) *http.Request {
				t.Helper()

				return httptest.NewRequest("POST", "http://heimdal.test.local/foobar", nil)
			},
			configureMocks: func(t *testing.T, repository *mocks2.MockRepository, rule *mocks4.MockRule) {
				t.Helper()

				rule.On("UpstreamURL", mock.MatchedBy(
					func(URL *url.URL) bool { return URL.String() == "http://heimdal.test.local/foobar" }),
				).Return(&url.URL{Scheme: "http", Host: "test.local", Path: "/foobar"})
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

				return httptest.NewRequest("POST", "http://heimdal.test.local/foobar", nil)
			},
			configureMocks: func(t *testing.T, repository *mocks2.MockRepository, rule *mocks4.MockRule) {
				t.Helper()

				rule.On("UpstreamURL", mock.MatchedBy(
					func(URL *url.URL) bool { return URL.String() == "http://heimdal.test.local/foobar" }),
				).Return(&url.URL{Scheme: "http", Host: "test.local", Path: "/foobar"})
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

			_, err := newHandler(handlerParams{
				App:             app,
				RulesRepository: repo,
				KeyStore:        ks,
				Config:          conf,
				Logger:          logger,
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
