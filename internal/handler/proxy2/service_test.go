package proxy2

import (
	"context"
	"fmt"
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
	"github.com/dadrus/heimdall/internal/handler/request"
	"github.com/dadrus/heimdall/internal/heimdall"
	mocks4 "github.com/dadrus/heimdall/internal/rules/rule/mocks"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestProxyService(t *testing.T) {
	t.Parallel()

	var (
		upstreamCalled       bool
		upstreamCheckRequest func(req *http.Request)

		upstreamResponseContentType string
		upstreamResponseContent     []byte
		upstreamResponseCode        int
	)

	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	defer upstreamSrv.Close()

	upstreamURL, err := url.Parse(upstreamSrv.URL)
	require.NoError(t, err)

	for _, tc := range []struct {
		uc               string
		serviceConf      config.ServiceConfig
		enableMetrics    bool
		createRequest    func(t *testing.T, host string) *http.Request
		configureMocks   func(t *testing.T, eh *mocks4.ExecutorMock)
		instructUpstream func(t *testing.T)
		assertResponse   func(t *testing.T, err error, resp *http.Response)
	}{
		{
			uc: "no rules configured",
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					context.TODO(),
					http.MethodGet,
					fmt.Sprintf("http://%s/foobar", host),
					nil,
				)
				require.NoError(t, err)

				return req
			},
			configureMocks: func(t *testing.T, eh *mocks4.ExecutorMock) {
				t.Helper()

				eh.EXPECT().Execute(mock.Anything, mock.Anything).Return(nil, heimdall.ErrNoRuleFound)
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
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					context.TODO(),
					http.MethodPost,
					fmt.Sprintf("http://%s/foobar", host),
					nil,
				)
				require.NoError(t, err)

				return req
			},
			configureMocks: func(t *testing.T, eh *mocks4.ExecutorMock) {
				t.Helper()

				eh.EXPECT().Execute(mock.Anything, mock.Anything).Return(nil, heimdall.ErrMethodNotAllowed)
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
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					context.TODO(),
					http.MethodPost,
					fmt.Sprintf("http://%s/foobar", host),
					nil,
				)
				require.NoError(t, err)

				return req
			},
			configureMocks: func(t *testing.T, eh *mocks4.ExecutorMock) {
				t.Helper()

				eh.EXPECT().Execute(mock.Anything, mock.Anything).Return(nil, heimdall.ErrConfiguration)
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
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					context.TODO(),
					http.MethodPost,
					fmt.Sprintf("http://%s/foobar", host),
					nil,
				)
				require.NoError(t, err)

				return req
			},
			configureMocks: func(t *testing.T, eh *mocks4.ExecutorMock) {
				t.Helper()

				eh.EXPECT().Execute(mock.Anything, mock.Anything).Return(nil, heimdall.ErrAuthentication)
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
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					context.TODO(),
					http.MethodPost,
					fmt.Sprintf("http://%s/foobar", host),
					nil,
				)
				require.NoError(t, err)

				return req
			},
			configureMocks: func(t *testing.T, eh *mocks4.ExecutorMock) {
				t.Helper()

				eh.EXPECT().Execute(mock.Anything, mock.Anything).Return(nil, heimdall.ErrAuthorization)
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
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					context.TODO(),
					http.MethodPost,
					fmt.Sprintf("http://%s/foobar", host),
					strings.NewReader("hello"))
				require.NoError(t, err)

				req.Header.Set("Content-Type", "text/html")
				req.Header.Set("X-Forwarded-Method", http.MethodGet)
				req.Header.Set("X-Forwarded-Uri", "/barfoo")

				return req
			},
			configureMocks: func(t *testing.T, eh *mocks4.ExecutorMock) {
				t.Helper()

				eh.EXPECT().Execute(
					mock.MatchedBy(func(ctx request.Context) bool {
						ctx.AddHeaderForUpstream("X-Foo-Bar", "baz")
						ctx.AddCookieForUpstream("X-Bar-Foo", "zab")

						pathMatched := ctx.Request().URL.Path == "/foobar"
						methodMatched := ctx.Request().Method == http.MethodPost

						return pathMatched && methodMatched
					}),
					mock.Anything,
				).Return(&url.URL{
					Scheme: upstreamURL.Scheme,
					Host:   upstreamURL.Host,
					Path:   "/foobar",
				}, nil)
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
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					context.TODO(),
					http.MethodPost,
					fmt.Sprintf("http://%s", host)+"/%5Bid%5D/foobar",
					strings.NewReader("hello"))
				require.NoError(t, err)

				req.Header.Set("Content-Type", "text/html")
				req.Header.Set("X-Forwarded-Method", http.MethodGet)

				return req
			},
			configureMocks: func(t *testing.T, eh *mocks4.ExecutorMock) {
				t.Helper()

				eh.EXPECT().Execute(
					mock.MatchedBy(func(ctx request.Context) bool {
						ctx.AddHeaderForUpstream("X-Foo-Bar", "baz")
						ctx.AddCookieForUpstream("X-Bar-Foo", "zab")

						pathMatched := ctx.Request().URL.Path == "/[id]/foobar"
						methodMatched := ctx.Request().Method == http.MethodGet

						return pathMatched && methodMatched
					}),
					mock.Anything,
				).Return(&url.URL{
					Scheme: upstreamURL.Scheme,
					Host:   upstreamURL.Host,
					Path:   "/[id]/foobar",
				}, nil)
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
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					context.TODO(),
					http.MethodPost,
					fmt.Sprintf("http://%s/foobar", host),
					strings.NewReader("hello"))
				require.NoError(t, err)

				req.Header.Set("Content-Type", "text/html")
				req.Header.Set("X-Forwarded-Path", "/%5Bbarfoo%5D")

				return req
			},
			configureMocks: func(t *testing.T, eh *mocks4.ExecutorMock) {
				t.Helper()

				eh.EXPECT().Execute(
					mock.MatchedBy(func(ctx request.Context) bool {
						ctx.AddHeaderForUpstream("X-Foo-Bar", "baz")
						ctx.AddCookieForUpstream("X-Bar-Foo", "zab")

						pathMatched := ctx.Request().URL.Path == "/[barfoo]"
						methodMatched := ctx.Request().Method == http.MethodPost

						return pathMatched && methodMatched
					}),
					mock.Anything,
				).Return(&url.URL{
					Scheme: upstreamURL.Scheme,
					Host:   upstreamURL.Host,
					Path:   "/[barfoo]",
				}, nil)
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
		{
			uc: "CORS test actual request",
			serviceConf: config.ServiceConfig{
				Timeout: config.Timeout{Read: 10 * time.Second},
				CORS: &config.CORS{
					AllowedMethods:   []string{http.MethodGet},
					AllowedOrigins:   []string{"https://foo.bar"},
					AllowedHeaders:   []string{"Content-Type"},
					ExposedHeaders:   []string{"X-Foo-Bar"},
					AllowCredentials: false,
					MaxAge:           1 * time.Second,
				},
			},
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					context.TODO(),
					http.MethodGet,
					fmt.Sprintf("http://%s/foobar", host),
					strings.NewReader("hello"))
				require.NoError(t, err)

				req.Header.Set("Content-Type", "text/html")
				req.Header.Set("Origin", "https://foo.bar")

				return req
			},
			configureMocks: func(t *testing.T, eh *mocks4.ExecutorMock) {
				t.Helper()

				eh.EXPECT().Execute(
					mock.MatchedBy(func(ctx request.Context) bool {
						ctx.AddHeaderForUpstream("X-Foo-Bar", "baz")

						pathMatched := ctx.Request().URL.Path == "/foobar"
						methodMatched := ctx.Request().Method == http.MethodGet

						return pathMatched && methodMatched
					}),
					mock.Anything,
				).Return(&url.URL{
					Scheme: upstreamURL.Scheme,
					Host:   upstreamURL.Host,
					Path:   "/bar",
				}, nil)
			},
			instructUpstream: func(t *testing.T) {
				t.Helper()

				upstreamCheckRequest = func(req *http.Request) {
					assert.Equal(t, http.MethodGet, req.Method)
					assert.Equal(t, "/bar", req.URL.Path)

					assert.Equal(t, "baz", req.Header.Get("X-Foo-Bar"))
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
				assert.Equal(t, "https://foo.bar", response.Header.Get("Access-Control-Allow-Origin"))
				assert.Equal(t, "Origin", response.Header.Get("Vary"))

				data, err := io.ReadAll(response.Body)
				require.NoError(t, err)
				assert.JSONEq(t, `{ "foo": "bar" }`, string(data))
			},
		},
		{
			uc: "CORS test preflight request",
			serviceConf: config.ServiceConfig{
				Timeout: config.Timeout{Read: 10 * time.Second},
				CORS: &config.CORS{
					AllowedMethods:   []string{http.MethodGet},
					AllowedOrigins:   []string{"https://foo.bar"},
					AllowedHeaders:   []string{"Content-Type"},
					ExposedHeaders:   []string{"X-Foo-Bar"},
					AllowCredentials: false,
					MaxAge:           1 * time.Second,
				},
			},
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					context.TODO(),
					http.MethodOptions,
					fmt.Sprintf("http://%s/foobar", host),
					nil)
				require.NoError(t, err)

				req.Header.Set("Origin", "https://foo.bar")
				req.Header.Set("Access-Control-Request-Method", http.MethodGet)

				return req
			},
			configureMocks: func(t *testing.T, eh *mocks4.ExecutorMock) { t.Helper() },
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.False(t, upstreamCalled)

				require.NoError(t, err)
				assert.Equal(t, http.StatusNoContent, response.StatusCode)

				assert.Equal(t, "https://foo.bar", response.Header.Get("Access-Control-Allow-Origin"))
				assert.Equal(t, http.MethodGet, response.Header.Get("Access-Control-Allow-Methods"))
				assert.Contains(t, response.Header["Vary"], "Origin")
				assert.Contains(t, response.Header["Vary"], "Access-Control-Request-Method")
				assert.Contains(t, response.Header["Vary"], "Access-Control-Request-Headers")
			},
		},
		{
			uc: "test metrics collection",
			serviceConf: config.ServiceConfig{
				Timeout: config.Timeout{Read: 10 * time.Second},
				CORS: &config.CORS{
					AllowedMethods:   []string{http.MethodGet},
					AllowedOrigins:   []string{"https://foo.bar"},
					AllowedHeaders:   []string{"Content-Type"},
					ExposedHeaders:   []string{"X-Foo-Bar"},
					AllowCredentials: false,
					MaxAge:           1 * time.Second,
				},
			},
			enableMetrics: true,
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					context.TODO(),
					http.MethodOptions,
					fmt.Sprintf("http://%s/foobar", host),
					nil)
				require.NoError(t, err)

				req.Header.Set("Origin", "https://foo.bar")
				req.Header.Set("Access-Control-Request-Method", http.MethodGet)

				return req
			},
			configureMocks: func(t *testing.T, eh *mocks4.ExecutorMock) { t.Helper() },
			assertResponse: func(t *testing.T, err error, response *http.Response) {
				t.Helper()

				require.False(t, upstreamCalled)

				require.NoError(t, err)
				assert.Equal(t, http.StatusNoContent, response.StatusCode)
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

			registry := prometheus.NewRegistry()

			port, err := testsupport.GetFreePort()
			require.NoError(t, err)

			proxyConf := tc.serviceConf
			proxyConf.Host = "127.0.0.1"
			proxyConf.Port = port

			conf := &config.Configuration{
				Serve:   config.ServeConfig{Proxy: proxyConf},
				Metrics: config.MetricsConfig{Enabled: tc.enableMetrics},
			}
			cch := mocks.NewCacheMock(t)
			eh := mocks4.NewExecutorMock(t)

			tc.configureMocks(t, eh)
			instructUpstream(t)

			client := &http.Client{Transport: &http.Transport{}}

			proxy := newService(serviceArgs{
				Config:     conf,
				Registerer: registry,
				Cache:      cch,
				Logger:     log.Logger,
				Executor:   eh,
			})
			defer proxy.Shutdown(context.Background())

			go func() {
				err := proxy.ListenAndServe()
				require.ErrorIs(t, err, http.ErrServerClosed)
			}()
			time.Sleep(50 * time.Millisecond)

			// WHEN
			resp, err := client.Do(tc.createRequest(t, proxy.Addr))

			// THEN
			if err == nil {
				defer resp.Body.Close()
			}

			tc.assertResponse(t, err, resp)

			metrics, err := registry.Gather()
			require.NoError(t, err)

			if tc.enableMetrics {
				require.NotEmpty(t, metrics)
			} else {
				require.Empty(t, metrics)
			}
		})
	}
}
