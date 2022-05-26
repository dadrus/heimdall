package decision

import (
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	mocks3 "github.com/dadrus/heimdall/internal/heimdall/mocks"
	mocks2 "github.com/dadrus/heimdall/internal/rules/mocks"
	mocks4 "github.com/dadrus/heimdall/internal/rules/rule/mocks"
)

var errTest = errors.New("test purpose error")

func TestHandleDecisionAPIRequest(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc             string
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

				repository.On("FindRule", mock.Anything).Return(nil, errTest)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusInternalServerError, response.StatusCode)

				data, err := ioutil.ReadAll(response.Body)
				require.NoError(t, err)
				assert.Equal(t, "Internal Server Error", string(data))
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
				assert.Equal(t, "Method Not Allowed", string(data))
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
				assert.Equal(t, "Unauthorized", string(data))
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
				rule.On("Execute", mock.MatchedBy(func(ctx *requestContext) bool {
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
				assert.Equal(t, "Forbidden", string(data))
			},
		},
		{
			uc: "rule execution succeeds and sets a response cookie and header",
			createRequest: func(t *testing.T) *http.Request {
				t.Helper()

				return httptest.NewRequest("POST", "/decisions", nil)
			},
			configureMocks: func(t *testing.T, repository *mocks2.MockRepository, rule *mocks4.MockRule) {
				t.Helper()

				rule.On("MatchesMethod", "POST").Return(true)
				rule.On("Execute", mock.MatchedBy(func(ctx *requestContext) bool {
					ctx.AddResponseHeader("X-Foo-Bar", "baz")
					ctx.AddResponseCookie("X-Bar-Foo", "zab")

					return true
				})).Return(nil)

				repository.On("FindRule", mock.Anything).Return(rule, nil)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusAccepted, response.StatusCode)

				data, err := ioutil.ReadAll(response.Body)
				require.NoError(t, err)
				assert.Equal(t, "Accepted", string(data))

				headerVal := response.Header.Get("X-Foo-Bar")
				assert.Equal(t, headerVal, "baz")

				cookies := response.Cookies()
				require.Len(t, cookies, 1)
				assert.Equal(t, "X-Bar-Foo", cookies[0].Name)
				assert.Equal(t, "zab", cookies[0].Value)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			conf := config.Configuration{}
			cch := &mocks.MockCache{}
			repo := &mocks2.MockRepository{}
			signer := &mocks3.MockJWTSigner{}
			rule := &mocks4.MockRule{}
			logger := log.Logger

			tc.configureMocks(t, repo, rule)

			app := newFiberApp(conf, cch, logger)

			_, err := newHandler(handlerParams{
				App:             app,
				RulesRepository: repo,
				Logger:          logger,
				Signer:          signer,
			})
			require.NoError(t, err)

			// WHEN
			resp, err := app.Test(tc.createRequest(t))

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
