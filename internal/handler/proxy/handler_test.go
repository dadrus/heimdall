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

package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	mocks4 "github.com/dadrus/heimdall/internal/rules/rule/mocks"
	"github.com/dadrus/heimdall/internal/x"
)

func TestHandleProxyEndpointRequest(t *testing.T) {
	t.Parallel()

	var (
		upstreamCalled       bool
		upstreamCheckRequest func(req *http.Request)

		upstreamResponseContentType string
		upstreamResponseContent     []byte
		upstreamResponseCode        int
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true

		upstreamCheckRequest(r)

		if upstreamResponseContent != nil {
			w.Header().Set("Content-Type", upstreamResponseContentType)
			w.Header().Set("Content-Length", strconv.Itoa(len(upstreamResponseContent)))
			_, err := w.Write(upstreamResponseContent)
			assert.NoError(t, err)
		}

		w.WriteHeader(upstreamResponseCode)
	}))
	defer srv.Close()

	upstreamURL, err := url.Parse(srv.URL)
	require.NoError(t, err)

	for _, tc := range []struct {
		uc               string
		serviceConf      config.ServiceConfig
		createRequest    func(t *testing.T) *http.Request
		configureMocks   func(t *testing.T, exec *mocks4.ExecutorMock)
		instructUpstream func(t *testing.T)
		assertResponse   func(t *testing.T, err error, response *http.Response)
	}{
		{
			uc: "no rules configured",
			createRequest: func(t *testing.T) *http.Request {
				t.Helper()

				return httptest.NewRequest(http.MethodGet, "http://heimdall.test.local/foobar", nil)
			},
			configureMocks: func(t *testing.T, exec *mocks4.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(mock.Anything).Return(nil, heimdall.ErrNoRuleFound)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.False(t, upstreamCalled)

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

				return httptest.NewRequest(http.MethodPost, "http://heimdall.test.local/foobar", nil)
			},
			configureMocks: func(t *testing.T, exec *mocks4.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(mock.Anything).Return(nil, heimdall.ErrMethodNotAllowed)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.False(t, upstreamCalled)

				require.NoError(t, err)
				assert.Equal(t, http.StatusMethodNotAllowed, response.StatusCode)

				data, err := io.ReadAll(response.Body)
				require.NoError(t, err)
				assert.Len(t, data, 0)
			},
		},
		{
			uc: "rule execution fails due to not configured upstream url",
			createRequest: func(t *testing.T) *http.Request {
				t.Helper()

				return httptest.NewRequest(http.MethodPost, "http://heimdall.test.local/foobar", nil)
			},
			configureMocks: func(t *testing.T, exec *mocks4.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(mock.Anything).Return(nil, heimdall.ErrConfiguration)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.False(t, upstreamCalled)

				require.NoError(t, err)
				assert.Equal(t, http.StatusInternalServerError, response.StatusCode)

				data, err := io.ReadAll(response.Body)
				require.NoError(t, err)
				assert.Len(t, data, 0)
			},
		},
		{
			uc: "rule execution fails with authentication error",
			createRequest: func(t *testing.T) *http.Request {
				t.Helper()

				return httptest.NewRequest(http.MethodPost, "http://heimdall.test.local/foobar", nil)
			},
			configureMocks: func(t *testing.T, exec *mocks4.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(mock.Anything).Return(nil, heimdall.ErrAuthentication)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.False(t, upstreamCalled)

				require.NoError(t, err)
				assert.Equal(t, http.StatusUnauthorized, response.StatusCode)

				data, err := io.ReadAll(response.Body)
				require.NoError(t, err)
				assert.Len(t, data, 0)
			},
		},
		{
			uc: "rule execution fails with pipeline authorization error",
			createRequest: func(t *testing.T) *http.Request {
				t.Helper()

				return httptest.NewRequest(http.MethodPost, "http://heimdall.test.local/foobar", nil)
			},
			configureMocks: func(t *testing.T, exec *mocks4.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(mock.Anything).Return(nil, heimdall.ErrAuthorization)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.False(t, upstreamCalled)

				require.NoError(t, err)
				assert.Equal(t, http.StatusForbidden, response.StatusCode)

				data, err := io.ReadAll(response.Body)
				require.NoError(t, err)
				assert.Len(t, data, 0)
			},
		},
		{
			uc: "successful rule execution - request method and path are taken from the real request " +
				"(trusted proxy not configured)",
			serviceConf: config.ServiceConfig{Timeout: config.Timeout{Read: 10 * time.Second}},
			createRequest: func(t *testing.T) *http.Request {
				t.Helper()

				req := httptest.NewRequest(
					http.MethodPost,
					"http://heimdall.test.local/foobar",
					strings.NewReader("hello"))

				req.Header.Set("Content-Type", "text/html")
				req.Header.Set("X-Forwarded-Method", http.MethodGet)
				req.Header.Set("X-Forwarded-Uri", "https://test.com/barfoo")

				return req
			},
			configureMocks: func(t *testing.T, exec *mocks4.ExecutorMock) {
				t.Helper()

				mut := mocks4.NewURIMutatorMock(t)
				mut.EXPECT().Mutate(mock.Anything).Return(&url.URL{
					Scheme: upstreamURL.Scheme,
					Host:   upstreamURL.Host,
					Path:   "/foobar",
				}, nil)

				exec.EXPECT().Execute(
					mock.MatchedBy(func(ctx heimdall.Context) bool {
						ctx.AddHeaderForUpstream("X-Foo-Bar", "baz")
						ctx.AddCookieForUpstream("X-Bar-Foo", "zab")

						pathMatched := ctx.Request().URL.Path == "/foobar"
						methodMatched := ctx.Request().Method == http.MethodPost

						return pathMatched && methodMatched
					}),
				).Return(mut, nil)
			},
			instructUpstream: func(t *testing.T) {
				t.Helper()

				upstreamCheckRequest = func(req *http.Request) {
					assert.Equal(t, http.MethodPost, req.Method)

					assert.Equal(t, "/foobar", req.URL.Path)

					assert.Equal(t, "baz", req.Header.Get("X-Foo-Bar"))
					cookie, err := req.Cookie("X-Bar-Foo")
					require.NoError(t, err)
					assert.Equal(t, "zab", cookie.Value)

					assert.Equal(t, "text/html", req.Header.Get("Content-Type"))

					data, err := io.ReadAll(req.Body)
					require.NoError(t, err)
					assert.Equal(t, "hello", string(data))
				}

				upstreamResponseContentType = "application/json"
				upstreamResponseContent = []byte(`{ "foo": "bar" }`)
				upstreamResponseCode = http.StatusOK
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.True(t, upstreamCalled)

				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, response.StatusCode)

				assert.Equal(t, "application/json", response.Header.Get("Content-Type"))

				data, err := io.ReadAll(response.Body)
				require.NoError(t, err)
				assert.JSONEq(t, `{ "foo": "bar" }`, string(data))
			},
		},
		{
			uc: "successful rule execution - request method is taken from the header " +
				"(trusted proxy configured)",
			serviceConf: config.ServiceConfig{
				Timeout:        config.Timeout{Read: 10 * time.Second},
				TrustedProxies: &[]string{"0.0.0.0/0"},
			},
			createRequest: func(t *testing.T) *http.Request {
				t.Helper()

				req := httptest.NewRequest(
					http.MethodPost,
					"http://heimdall.test.local/%5Bid%5D/foobar",
					strings.NewReader("hello"))

				req.Header.Set("Content-Type", "text/html")
				req.Header.Set("X-Forwarded-Method", http.MethodGet)

				return req
			},
			configureMocks: func(t *testing.T, exec *mocks4.ExecutorMock) {
				t.Helper()

				mut := mocks4.NewURIMutatorMock(t)
				mut.EXPECT().Mutate(mock.Anything).Return(&url.URL{
					Scheme: upstreamURL.Scheme,
					Host:   upstreamURL.Host,
					Path:   "/[id]/foobar",
				}, nil)

				exec.EXPECT().Execute(
					mock.MatchedBy(func(ctx heimdall.Context) bool {
						ctx.AddHeaderForUpstream("X-Foo-Bar", "baz")
						ctx.AddCookieForUpstream("X-Bar-Foo", "zab")

						pathMatched := ctx.Request().URL.Path == "/[id]/foobar"
						methodMatched := ctx.Request().Method == http.MethodGet

						return pathMatched && methodMatched
					}),
				).Return(mut, nil)
			},
			instructUpstream: func(t *testing.T) {
				t.Helper()

				upstreamCheckRequest = func(req *http.Request) {
					assert.Equal(t, http.MethodGet, req.Method)
					assert.Equal(t, "/[id]/foobar", req.URL.Path)

					assert.Equal(t, "baz", req.Header.Get("X-Foo-Bar"))
					cookie, err := req.Cookie("X-Bar-Foo")
					require.NoError(t, err)
					assert.Equal(t, "zab", cookie.Value)

					assert.Equal(t, "text/html", req.Header.Get("Content-Type"))

					data, err := io.ReadAll(req.Body)
					require.NoError(t, err)
					assert.Equal(t, "hello", string(data))
				}

				upstreamResponseContentType = "application/json"
				upstreamResponseContent = []byte(`{ "foo": "bar" }`)
				upstreamResponseCode = http.StatusOK
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.True(t, upstreamCalled)

				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, response.StatusCode)

				assert.Equal(t, "application/json", response.Header.Get("Content-Type"))

				data, err := io.ReadAll(response.Body)
				require.NoError(t, err)
				assert.JSONEq(t, `{ "foo": "bar" }`, string(data))
			},
		},
		{
			uc: "successful rule execution - request path is taken from the header " +
				"(trusted proxy configured)",
			serviceConf: config.ServiceConfig{
				Timeout:        config.Timeout{Read: 10 * time.Second},
				TrustedProxies: &[]string{"0.0.0.0/0"},
			},
			createRequest: func(t *testing.T) *http.Request {
				t.Helper()

				req := httptest.NewRequest(
					http.MethodPost,
					"http://heimdall.test.local/foobar",
					strings.NewReader("hello"))

				req.Header.Set("Content-Type", "text/html")
				req.Header.Set("X-Forwarded-Path", "/%5Bbarfoo%5D")

				return req
			},
			configureMocks: func(t *testing.T, exec *mocks4.ExecutorMock) {
				t.Helper()

				mut := mocks4.NewURIMutatorMock(t)
				mut.EXPECT().Mutate(mock.Anything).Return(&url.URL{
					Scheme: upstreamURL.Scheme,
					Host:   upstreamURL.Host,
					Path:   "/[barfoo]",
				}, nil)

				exec.EXPECT().Execute(
					mock.MatchedBy(func(ctx heimdall.Context) bool {
						ctx.AddHeaderForUpstream("X-Foo-Bar", "baz")
						ctx.AddCookieForUpstream("X-Bar-Foo", "zab")

						pathMatched := ctx.Request().URL.Path == "/[barfoo]"
						methodMatched := ctx.Request().Method == http.MethodPost

						return pathMatched && methodMatched
					}),
				).Return(mut, nil)
			},
			instructUpstream: func(t *testing.T) {
				t.Helper()

				upstreamCheckRequest = func(req *http.Request) {
					assert.Equal(t, http.MethodPost, req.Method)
					assert.Equal(t, "/[barfoo]", req.URL.Path)

					assert.Equal(t, "baz", req.Header.Get("X-Foo-Bar"))
					cookie, err := req.Cookie("X-Bar-Foo")
					require.NoError(t, err)
					assert.Equal(t, "zab", cookie.Value)

					assert.Equal(t, "text/html", req.Header.Get("Content-Type"))

					data, err := io.ReadAll(req.Body)
					require.NoError(t, err)
					assert.Equal(t, "hello", string(data))
				}

				upstreamResponseContentType = "application/json"
				upstreamResponseContent = []byte(`{ "foo": "bar" }`)
				upstreamResponseCode = http.StatusOK
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.True(t, upstreamCalled)

				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, response.StatusCode)

				assert.Equal(t, "application/json", response.Header.Get("Content-Type"))

				data, err := io.ReadAll(response.Body)
				require.NoError(t, err)
				assert.JSONEq(t, `{ "foo": "bar" }`, string(data))
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			upstreamCalled = false
			upstreamResponseContentType = ""
			upstreamResponseContent = nil
			upstreamCheckRequest = func(*http.Request) { t.Helper() }

			instructUpstream := x.IfThenElse(tc.instructUpstream != nil,
				tc.instructUpstream,
				func(t *testing.T) { t.Helper() })

			conf := &config.Configuration{Serve: config.ServeConfig{Proxy: tc.serviceConf}}
			cch := mocks.NewCacheMock(t)
			exec := mocks4.NewExecutorMock(t)
			logger := log.Logger

			tc.configureMocks(t, exec)
			instructUpstream(t)

			app := newApp(appArgs{
				Config:     conf,
				Registerer: prometheus.NewRegistry(),
				Cache:      cch,
				Logger:     log.Logger,
			})

			defer app.Shutdown()

			_, err := newHandler(handlerArgs{
				App:    app,
				Exec:   exec,
				Config: conf,
				Logger: logger,
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
