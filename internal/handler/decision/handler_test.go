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

package decision

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	mocks4 "github.com/dadrus/heimdall/internal/rules/rule/mocks"
)

// nolint: gocognit, cyclop, maintidx
func TestHandleDecisionEndpointRequest(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc             string
		serviceConf    config.ServiceConfig
		createRequest  func(t *testing.T) *http.Request
		configureMocks func(t *testing.T, repository *mocks4.RepositoryMock, rule *mocks4.RuleMock)
		assertResponse func(t *testing.T, err error, response *http.Response)
	}{
		{
			uc: "no rules configured",
			createRequest: func(t *testing.T) *http.Request {
				t.Helper()

				return httptest.NewRequest(http.MethodGet, "/", nil)
			},
			configureMocks: func(t *testing.T, repository *mocks4.RepositoryMock, rule *mocks4.RuleMock) {
				t.Helper()

				repository.EXPECT().FindRule(mock.Anything).Return(nil, heimdall.ErrNoRuleFound)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusNotFound, response.StatusCode)

				data, err := io.ReadAll(response.Body)
				require.NoError(t, err)
				assert.Len(t, data, 0)
			},
		},
		{
			uc: "rule doesn't match method",
			createRequest: func(t *testing.T) *http.Request {
				t.Helper()

				return httptest.NewRequest(http.MethodPost, "/", nil)
			},
			configureMocks: func(t *testing.T, repository *mocks4.RepositoryMock, rule *mocks4.RuleMock) {
				t.Helper()

				rule.EXPECT().MatchesMethod(http.MethodPost).Return(false)
				repository.EXPECT().FindRule(mock.Anything).Return(rule, nil)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusMethodNotAllowed, response.StatusCode)

				data, err := io.ReadAll(response.Body)
				require.NoError(t, err)
				assert.Len(t, data, 0)
			},
		},
		{
			uc: "rule execution fails with authentication error",
			createRequest: func(t *testing.T) *http.Request {
				t.Helper()

				return httptest.NewRequest(http.MethodPost, "/", nil)
			},
			configureMocks: func(t *testing.T, repository *mocks4.RepositoryMock, rule *mocks4.RuleMock) {
				t.Helper()

				rule.EXPECT().MatchesMethod(http.MethodPost).Return(true)
				rule.EXPECT().Execute(mock.Anything).Return(nil, heimdall.ErrAuthentication)

				repository.EXPECT().FindRule(mock.Anything).Return(rule, nil)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusUnauthorized, response.StatusCode)

				data, err := io.ReadAll(response.Body)
				require.NoError(t, err)
				assert.Len(t, data, 0)
			},
		},
		{
			uc: "rule execution fails with authorization error",
			createRequest: func(t *testing.T) *http.Request {
				t.Helper()

				return httptest.NewRequest(http.MethodPost, "/", nil)
			},
			configureMocks: func(t *testing.T, repository *mocks4.RepositoryMock, rule *mocks4.RuleMock) {
				t.Helper()

				rule.EXPECT().MatchesMethod(http.MethodPost).Return(true)
				rule.EXPECT().Execute(mock.MatchedBy(func(ctx heimdall.Context) bool {
					ctx.SetPipelineError(heimdall.ErrAuthorization)

					return true
				})).Return(nil, nil)

				repository.EXPECT().FindRule(mock.Anything).Return(rule, nil)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusForbidden, response.StatusCode)

				data, err := io.ReadAll(response.Body)
				require.NoError(t, err)
				assert.Len(t, data, 0)
			},
		},
		{
			uc: "successful rule execution - request method, path and hostname " +
				"are taken from the real request (trusted proxy not configured)",
			createRequest: func(t *testing.T) *http.Request {
				t.Helper()

				req := httptest.NewRequest(
					http.MethodPost,
					"http://heimdall.test.local/foobar",
					nil)

				req.Header.Set("X-Forwarded-Proto", "https")
				req.Header.Set("X-Forwarded-Host", "test.com")
				req.Header.Set("X-Forwarded-Path", "bar")
				req.Header.Set("X-Forwarded-Method", http.MethodGet)

				return req
			},
			configureMocks: func(t *testing.T, repository *mocks4.RepositoryMock, rule *mocks4.RuleMock) {
				t.Helper()

				rule.EXPECT().MatchesMethod(http.MethodPost).Return(true)
				rule.EXPECT().Execute(mock.MatchedBy(func(ctx heimdall.Context) bool {
					ctx.AddHeaderForUpstream("X-Foo-Bar", "baz")
					ctx.AddCookieForUpstream("X-Bar-Foo", "zab")

					return true
				})).Return(&url.URL{Scheme: "http", Host: "heimdall.test.local", Path: "/foobar"}, nil)

				repository.EXPECT().FindRule(mock.MatchedBy(func(reqURL *url.URL) bool {
					return reqURL.Scheme == "http" && reqURL.Host == "heimdall.test.local" && reqURL.Path == "/foobar"
				})).Return(rule, nil)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, response.StatusCode)

				data, err := io.ReadAll(response.Body)
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
				"are not taken from the headers (trusted proxy not configured)",
			createRequest: func(t *testing.T) *http.Request {
				t.Helper()

				req := httptest.NewRequest(
					http.MethodPost,
					"http://heimdall.test.local/foobar",
					nil)

				req.Header.Set("X-Forwarded-Proto", "https")
				req.Header.Set("X-Forwarded-Host", "test.com")
				req.Header.Set("X-Forwarded-Path", "bar")
				req.Header.Set("X-Forwarded-Method", http.MethodGet)

				return req
			},
			configureMocks: func(t *testing.T, repository *mocks4.RepositoryMock, rule *mocks4.RuleMock) {
				t.Helper()

				rule.EXPECT().MatchesMethod(http.MethodPost).Return(true)
				rule.EXPECT().Execute(mock.MatchedBy(func(ctx heimdall.Context) bool {
					ctx.AddHeaderForUpstream("X-Foo-Bar", "baz")
					ctx.AddCookieForUpstream("X-Bar-Foo", "zab")

					return true
				})).Return(&url.URL{Scheme: "https", Host: "test.com", Path: "/bar"}, nil)

				repository.EXPECT().FindRule(mock.MatchedBy(func(reqURL *url.URL) bool {
					return reqURL.Scheme == "http" && reqURL.Host == "heimdall.test.local" && reqURL.Path == "/foobar"
				})).Return(rule, nil)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, response.StatusCode)

				data, err := io.ReadAll(response.Body)
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
					http.MethodPost,
					"http://heimdall.test.local/foobar",
					nil)

				req.Header.Set("X-Forwarded-Proto", "https")
				req.Header.Set("X-Forwarded-Host", "test.com")
				req.Header.Set("X-Forwarded-Path", "bar")
				req.Header.Set("X-Forwarded-Method", http.MethodGet)

				return req
			},
			configureMocks: func(t *testing.T, repository *mocks4.RepositoryMock, rule *mocks4.RuleMock) {
				t.Helper()

				rule.EXPECT().MatchesMethod(http.MethodPost).Return(true)
				rule.EXPECT().Execute(mock.MatchedBy(func(ctx heimdall.Context) bool {
					ctx.AddHeaderForUpstream("X-Foo-Bar", "baz")
					ctx.AddCookieForUpstream("X-Bar-Foo", "zab")

					return true
				})).Return(&url.URL{Scheme: "http", Host: "heimdall.test.local", Path: "/foobar"}, nil)

				repository.EXPECT().FindRule(mock.MatchedBy(func(reqURL *url.URL) bool {
					return reqURL.Scheme == "http" && reqURL.Host == "heimdall.test.local" && reqURL.Path == "/foobar"
				})).Return(rule, nil)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, response.StatusCode)

				data, err := io.ReadAll(response.Body)
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
					http.MethodPost,
					"http://heimdall.test.local/foobar",
					nil)

				req.Header.Set("X-Forwarded-Method", http.MethodGet)

				return req
			},
			configureMocks: func(t *testing.T, repository *mocks4.RepositoryMock, rule *mocks4.RuleMock) {
				t.Helper()

				rule.EXPECT().MatchesMethod(http.MethodGet).Return(true)
				rule.EXPECT().Execute(mock.Anything).
					Return(&url.URL{Scheme: "http", Host: "heimdall.test.local", Path: "/foobar"}, nil)

				repository.EXPECT().FindRule(mock.MatchedBy(func(reqURL *url.URL) bool {
					return reqURL.Scheme == "http" && reqURL.Host == "heimdall.test.local" && reqURL.Path == "/foobar"
				})).Return(rule, nil)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, response.StatusCode)
			},
		},
		{
			uc: "successful rule execution - only host is sent via header" +
				"(trusted proxy configured and matches host)",
			serviceConf: config.ServiceConfig{TrustedProxies: &[]string{"0.0.0.0/0"}},
			createRequest: func(t *testing.T) *http.Request {
				t.Helper()

				req := httptest.NewRequest(
					http.MethodPost,
					"http://heimdall.test.local/foobar",
					nil)

				req.Header.Set("X-Forwarded-Host", "test.com")

				return req
			},
			configureMocks: func(t *testing.T, repository *mocks4.RepositoryMock, rule *mocks4.RuleMock) {
				t.Helper()

				rule.EXPECT().MatchesMethod(http.MethodPost).Return(true)
				rule.EXPECT().Execute(mock.Anything).
					Return(&url.URL{Scheme: "http", Host: "test.com", Path: "/foobar"}, nil)

				repository.EXPECT().FindRule(mock.MatchedBy(func(reqURL *url.URL) bool {
					return reqURL.Scheme == "http" && reqURL.Host == "test.com" && reqURL.Path == "/foobar"
				})).Return(rule, nil)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, response.StatusCode)
			},
		},
		{
			uc: "successful rule execution - only path is sent via header" +
				"(trusted proxy configured and matches host)",
			serviceConf: config.ServiceConfig{TrustedProxies: &[]string{"0.0.0.0/0"}},
			createRequest: func(t *testing.T) *http.Request {
				t.Helper()

				req := httptest.NewRequest(
					http.MethodPost,
					"http://heimdall.test.local/foobar",
					nil)

				req.Header.Set("X-Forwarded-Path", "bar")

				return req
			},
			configureMocks: func(t *testing.T, repository *mocks4.RepositoryMock, rule *mocks4.RuleMock) {
				t.Helper()

				rule.EXPECT().MatchesMethod(http.MethodPost).Return(true)
				rule.EXPECT().Execute(mock.Anything).
					Return(&url.URL{Scheme: "http", Host: "heimdall.test.local", Path: "/bar"}, nil)

				repository.EXPECT().FindRule(mock.MatchedBy(func(reqURL *url.URL) bool {
					return reqURL.Scheme == "http" && reqURL.Host == "heimdall.test.local" && reqURL.Path == "bar"
				})).Return(rule, nil)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, response.StatusCode)
			},
		},
		{
			uc: "successful rule execution - only scheme is sent via header" +
				"(trusted proxy configured and matches host)",
			serviceConf: config.ServiceConfig{TrustedProxies: &[]string{"0.0.0.0/0"}},
			createRequest: func(t *testing.T) *http.Request {
				t.Helper()

				req := httptest.NewRequest(
					http.MethodPost,
					"http://heimdall.test.local/foobar",
					nil)

				req.Header.Set("X-Forwarded-Proto", "https")

				return req
			},
			configureMocks: func(t *testing.T, repository *mocks4.RepositoryMock, rule *mocks4.RuleMock) {
				t.Helper()

				rule.EXPECT().MatchesMethod(http.MethodPost).Return(true)
				rule.EXPECT().Execute(mock.Anything).
					Return(&url.URL{Scheme: "https", Host: "heimdall.test.local", Path: "/foobar"}, nil)

				repository.EXPECT().FindRule(mock.MatchedBy(func(reqURL *url.URL) bool {
					return reqURL.Scheme == "https" && reqURL.Host == "heimdall.test.local" && reqURL.Path == "/foobar"
				})).Return(rule, nil)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, response.StatusCode)
			},
		},
		{
			uc: "successful rule execution - scheme, host, path and method sent via header" +
				"(trusted proxy configured and matches host)",
			serviceConf: config.ServiceConfig{TrustedProxies: &[]string{"0.0.0.0/0"}},
			createRequest: func(t *testing.T) *http.Request {
				t.Helper()

				req := httptest.NewRequest(
					http.MethodPost,
					"http://heimdall.test.local/foobar",
					nil)

				req.Header.Set("X-Forwarded-Proto", "https")
				req.Header.Set("X-Forwarded-Host", "test.com")
				req.Header.Set("X-Forwarded-Path", "bar")
				req.Header.Set("X-Forwarded-Method", http.MethodPatch)

				return req
			},
			configureMocks: func(t *testing.T, repository *mocks4.RepositoryMock, rule *mocks4.RuleMock) {
				t.Helper()

				rule.EXPECT().MatchesMethod(http.MethodPatch).Return(true)
				rule.EXPECT().Execute(mock.Anything).
					Return(&url.URL{Scheme: "https", Host: "test.com", Path: "/bar"}, nil)

				repository.EXPECT().FindRule(mock.MatchedBy(func(reqURL *url.URL) bool {
					return reqURL.Scheme == "https" && reqURL.Host == "test.com" && reqURL.Path == "bar"
				})).Return(rule, nil)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, response.StatusCode)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			conf := &config.Configuration{Serve: config.ServeConfig{Decision: tc.serviceConf}}
			cch := &mocks.MockCache{}
			repo := mocks4.NewRepositoryMock(t)
			rule := mocks4.NewRuleMock(t)
			logger := log.Logger

			tc.configureMocks(t, repo, rule)

			app := newApp(appArgs{
				Config:     conf,
				Registerer: prometheus.NewRegistry(),
				Cache:      cch,
				Logger:     log.Logger,
			})

			defer app.Shutdown() // nolint: errcheck

			_, err := newHandler(handlerArgs{
				App:             app,
				RulesRepository: repo,
				Logger:          logger,
				Config:          conf,
			})
			require.NoError(t, err)

			// WHEN
			resp, err := app.Test(tc.createRequest(t), -1)

			// THEN
			if err == nil {
				defer resp.Body.Close()
			}

			tc.assertResponse(t, err, resp)
		})
	}
}
