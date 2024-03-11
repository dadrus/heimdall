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
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/listener"
	"github.com/dadrus/heimdall/internal/heimdall"
	mocks4 "github.com/dadrus/heimdall/internal/rules/rule/mocks"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestHandleDecisionEndpointRequest(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc             string
		serviceConf    config.ServiceConfig
		createRequest  func(t *testing.T, host string) *http.Request
		configureMocks func(t *testing.T, exec *mocks4.ExecutorMock)
		assertResponse func(t *testing.T, err error, response *http.Response)
	}{
		{
			uc: "no rules configured",
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					context.TODO(),
					http.MethodGet,
					fmt.Sprintf("http://%s/", host),
					nil,
				)
				require.NoError(t, err)

				return req
			},
			configureMocks: func(t *testing.T, exec *mocks4.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(mock.Anything).Return(nil, heimdall.ErrNoRuleFound)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusNotFound, response.StatusCode)

				data, err := io.ReadAll(response.Body)
				require.NoError(t, err)
				assert.Empty(t, data)
			},
		},
		{
			uc: "rule doesn't match method",
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					context.TODO(),
					http.MethodPost,
					fmt.Sprintf("http://%s/", host),
					nil,
				)
				require.NoError(t, err)

				return req
			},
			configureMocks: func(t *testing.T, exec *mocks4.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(mock.Anything).Return(nil, heimdall.ErrMethodNotAllowed)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusMethodNotAllowed, response.StatusCode)

				data, err := io.ReadAll(response.Body)
				require.NoError(t, err)
				assert.Empty(t, data)
			},
		},
		{
			uc: "rule execution fails with authentication error",
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					context.TODO(),
					http.MethodPost,
					fmt.Sprintf("http://%s/", host),
					nil,
				)
				require.NoError(t, err)

				return req
			},
			configureMocks: func(t *testing.T, exec *mocks4.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(mock.Anything).Return(nil, heimdall.ErrAuthentication)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusUnauthorized, response.StatusCode)

				data, err := io.ReadAll(response.Body)
				require.NoError(t, err)
				assert.Empty(t, data)
			},
		},
		{
			uc: "rule execution fails with authorization error",
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					context.TODO(),
					http.MethodPost,
					fmt.Sprintf("http://%s/", host),
					nil,
				)
				require.NoError(t, err)

				return req
			},
			configureMocks: func(t *testing.T, exec *mocks4.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(mock.Anything).Return(nil, heimdall.ErrAuthorization)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusForbidden, response.StatusCode)

				data, err := io.ReadAll(response.Body)
				require.NoError(t, err)
				assert.Empty(t, data)
			},
		},
		{
			uc: "successful rule execution - request method, path and hostname " +
				"are taken from the real request (trusted proxy not configured)",
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					context.TODO(),
					http.MethodPost,
					fmt.Sprintf("http://%s/foobar", host),
					nil,
				)
				require.NoError(t, err)

				req.Header.Set("X-Forwarded-Proto", "https")
				req.Header.Set("X-Forwarded-Host", "test.com")
				req.Header.Set("X-Forwarded-Uri", "/bar")
				req.Header.Set("X-Forwarded-Method", http.MethodGet)

				return req
			},
			configureMocks: func(t *testing.T, exec *mocks4.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(
					mock.MatchedBy(func(ctx heimdall.Context) bool {
						ctx.AddHeaderForUpstream("X-Foo-Bar", "baz")
						ctx.AddCookieForUpstream("X-Bar-Foo", "zab")

						pathMatched := ctx.Request().URL.Path == "/foobar"
						methodMatched := ctx.Request().Method == http.MethodPost

						return pathMatched && methodMatched
					}),
				).Return(nil, nil)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, response.StatusCode)

				data, err := io.ReadAll(response.Body)
				require.NoError(t, err)
				assert.Empty(t, data)

				headerVal := response.Header.Get("X-Foo-Bar")
				assert.Equal(t, "baz", headerVal)

				cookies := response.Cookies()
				require.Len(t, cookies, 1)
				assert.Equal(t, "X-Bar-Foo", cookies[0].Name)
				assert.Equal(t, "zab", cookies[0].Value)
			},
		},
		{
			uc: "successful rule execution - request method, path and hostname " +
				"are not taken from the headers (trusted proxy not configured)",
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					context.TODO(),
					http.MethodPost,
					fmt.Sprintf("http://%s/foobar", host),
					nil,
				)
				require.NoError(t, err)

				req.Header.Set("X-Forwarded-Proto", "https")
				req.Header.Set("X-Forwarded-Host", "test.com")
				req.Header.Set("X-Forwarded-Uri", "/bar")
				req.Header.Set("X-Forwarded-Method", http.MethodGet)

				return req
			},
			configureMocks: func(t *testing.T, exec *mocks4.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(
					mock.MatchedBy(func(ctx heimdall.Context) bool {
						ctx.AddHeaderForUpstream("X-Foo-Bar", "baz")
						ctx.AddCookieForUpstream("X-Bar-Foo", "zab")

						ctx.AddHeaderForUpstream("X-Foo-Bar", "baz")
						ctx.AddCookieForUpstream("X-Bar-Foo", "zab")

						pathMatched := ctx.Request().URL.Path == "/foobar"
						methodMatched := ctx.Request().Method == http.MethodPost
						schemeMatched := ctx.Request().URL.Scheme == "http"
						hostMatched := ctx.Request().URL.Host != "test.com"

						return pathMatched && methodMatched && schemeMatched && hostMatched
					}),
				).Return(nil, nil)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, response.StatusCode)

				data, err := io.ReadAll(response.Body)
				require.NoError(t, err)
				assert.Empty(t, data)

				headerVal := response.Header.Get("X-Foo-Bar")
				assert.Equal(t, "baz", headerVal)

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
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					context.TODO(),
					http.MethodPost,
					fmt.Sprintf("http://%s/foobar", host),
					nil,
				)
				require.NoError(t, err)

				req.Header.Set("X-Forwarded-Proto", "https")
				req.Header.Set("X-Forwarded-Host", "test.com")
				req.Header.Set("X-Forwarded-Uri", "/bar")
				req.Header.Set("X-Forwarded-Method", http.MethodGet)

				return req
			},
			configureMocks: func(t *testing.T, exec *mocks4.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(
					mock.MatchedBy(func(ctx heimdall.Context) bool {
						ctx.AddHeaderForUpstream("X-Foo-Bar", "baz")
						ctx.AddCookieForUpstream("X-Bar-Foo", "zab")

						pathMatched := ctx.Request().URL.Path == "/foobar"
						methodMatched := ctx.Request().Method == http.MethodPost
						schemeMatched := ctx.Request().URL.Scheme == "http"
						hostMatched := ctx.Request().URL.Host != "test.com"

						return pathMatched && methodMatched && schemeMatched && hostMatched
					}),
				).Return(nil, nil)
			},
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, response.StatusCode)

				data, err := io.ReadAll(response.Body)
				require.NoError(t, err)
				assert.Empty(t, data)

				headerVal := response.Header.Get("X-Foo-Bar")
				assert.Equal(t, "baz", headerVal)

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
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					context.TODO(),
					http.MethodPost,
					fmt.Sprintf("http://%s/foobar", host),
					nil,
				)
				require.NoError(t, err)

				req.Header.Set("X-Forwarded-Method", http.MethodGet)

				return req
			},
			configureMocks: func(t *testing.T, exec *mocks4.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(
					mock.MatchedBy(func(ctx heimdall.Context) bool {
						req := ctx.Request()

						return req.URL.Scheme == "http" &&
							req.URL.Path == "/foobar" &&
							req.Method == http.MethodGet
					}),
				).Return(nil, nil)
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
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					context.TODO(),
					http.MethodPost,
					fmt.Sprintf("http://%s/foobar", host),
					nil,
				)
				require.NoError(t, err)

				req.Header.Set("X-Forwarded-Host", "test.com")

				return req
			},
			configureMocks: func(t *testing.T, exec *mocks4.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(
					mock.MatchedBy(func(ctx heimdall.Context) bool {
						req := ctx.Request()

						return req.URL.Scheme == "http" &&
							req.URL.Host == "test.com" &&
							req.URL.Path == "/foobar" &&
							req.Method == http.MethodPost
					}),
				).Return(nil, nil)
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
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					context.TODO(),
					http.MethodPost,
					fmt.Sprintf("http://%s/foobar", host),
					nil,
				)
				require.NoError(t, err)

				req.Header.Set("X-Forwarded-Uri", "/bar")

				return req
			},
			configureMocks: func(t *testing.T, exec *mocks4.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(
					mock.MatchedBy(func(ctx heimdall.Context) bool {
						req := ctx.Request()

						return req.URL.Scheme == "http" &&
							req.URL.Path == "/bar" &&
							req.Method == http.MethodPost
					}),
				).Return(nil, nil)
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
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					context.TODO(),
					http.MethodPost,
					fmt.Sprintf("http://%s/foobar", host),
					nil,
				)
				require.NoError(t, err)

				req.Header.Set("X-Forwarded-Proto", "https")

				return req
			},
			configureMocks: func(t *testing.T, exec *mocks4.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(
					mock.MatchedBy(func(ctx heimdall.Context) bool {
						req := ctx.Request()

						return req.URL.Scheme == "https" &&
							req.URL.Path == "/foobar" &&
							req.Method == http.MethodPost
					}),
				).Return(nil, nil)
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
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					context.TODO(),
					http.MethodPost,
					fmt.Sprintf("http://%s/foobar", host),
					nil,
				)
				require.NoError(t, err)

				req.Header.Set("X-Forwarded-Proto", "https")
				req.Header.Set("X-Forwarded-Host", "test.com")
				req.Header.Set("X-Forwarded-Uri", "/bar")
				req.Header.Set("X-Forwarded-Method", http.MethodPatch)

				return req
			},
			configureMocks: func(t *testing.T, exec *mocks4.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(
					mock.MatchedBy(func(ctx heimdall.Context) bool {
						req := ctx.Request()

						return req.URL.Scheme == "https" &&
							req.URL.Host == "test.com" &&
							req.URL.Path == "/bar" &&
							req.Method == http.MethodPatch
					}),
				).Return(nil, nil)
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
			port, err := testsupport.GetFreePort()
			require.NoError(t, err)

			srvConf := tc.serviceConf
			srvConf.Host = "127.0.0.1"
			srvConf.Port = port

			listener, err := listener.New("tcp", srvConf.Address(), srvConf.TLS, nil)
			require.NoError(t, err)

			conf := &config.Configuration{Serve: config.ServeConfig{Decision: srvConf}}
			cch := mocks.NewCacheMock(t)
			exec := mocks4.NewExecutorMock(t)

			tc.configureMocks(t, exec)

			client := &http.Client{Transport: &http.Transport{}}

			decision := newService(conf, cch, log.Logger, exec, nil)
			defer decision.Shutdown(context.Background())

			go func() {
				decision.Serve(listener)
			}()

			time.Sleep(50 * time.Millisecond)

			// WHEN
			resp, err := client.Do(tc.createRequest(t, srvConf.Address()))

			// THEN
			if err == nil {
				defer resp.Body.Close()
			}

			tc.assertResponse(t, err, resp)
		})
	}
}
