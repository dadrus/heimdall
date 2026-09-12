// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/inhies/go-bytesize"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"

	"github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/listener"
	"github.com/dadrus/heimdall/internal/pipeline"
	mocks2 "github.com/dadrus/heimdall/internal/pipeline/mocks"
	"github.com/dadrus/heimdall/internal/secrets"
	secretsmocks "github.com/dadrus/heimdall/internal/secrets/mocks"
	secrettypes "github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/stringx"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

type testExecutor func(pipeline.ExecutionContext) error

func (e testExecutor) Execute(ctx pipeline.ExecutionContext) error { return e(ctx) }

type testUpstreamTarget struct {
	targetURL         url.URL
	forwardHostHeader bool
}

func (t testUpstreamTarget) ApplyTo(targetURL *url.URL) { *targetURL = t.targetURL }
func (t testUpstreamTarget) ForwardHostHeader() bool    { return t.forwardHostHeader }

func TestNewService(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		tls              *config.TLS
		http2            bool
		unencryptedHTTP2 bool
	}{
		"cleartext enables http1 and h2c": {
			unencryptedHTTP2: true,
		},
		"tls enables http1 and http2": {
			tls:   &config.TLS{},
			http2: true,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			conf := &config.Configuration{}

			conf.Serve.TLS = tc.tls
			conf.Serve.Timeout.Read = 98 * time.Second
			conf.Serve.Timeout.Write = 99 * time.Second
			conf.Serve.Requests.ReadTimeout = 10 * time.Second
			conf.Serve.Requests.Headers.MaxSize = 42 * bytesize.KB
			conf.Serve.Requests.Headers.ReadTimeout = 11 * time.Second
			conf.Serve.Responses.WriteTimeout = 12 * time.Second
			conf.Serve.Responses.WriteIdleTimeout = 19 * time.Second
			conf.Serve.Connections.IdleTimeout = 13 * time.Second
			conf.Serve.Connections.WriteIdleTimeout = 14 * time.Second
			conf.Serve.Connections.Streams.MaxConcurrent = 17
			conf.Serve.Connections.Liveness.ProbeAfter = 15 * time.Second
			conf.Serve.Connections.Liveness.ProbeTimeout = 16 * time.Second

			// WHEN
			srv := newService(
				conf,
				mocks.NewCacheMock(t),
				log.Logger,
				mocks2.NewExecutorMock(t),
			)

			// THEN
			assert.NotNil(t, srv.Handler)

			assert.Equal(t, 10*time.Second, srv.ReadTimeout)
			assert.Equal(t, 11*time.Second, srv.ReadHeaderTimeout)
			assert.Equal(t, 12*time.Second, srv.WriteTimeout)
			assert.Equal(t, 13*time.Second, srv.IdleTimeout)
			assert.Equal(t, int(42*bytesize.KB), srv.MaxHeaderBytes)

			require.NotNil(t, srv.HTTP2)
			assert.Equal(t, 17, srv.HTTP2.MaxConcurrentStreams)
			assert.Equal(t, 15*time.Second, srv.HTTP2.SendPingTimeout)
			assert.Equal(t, 16*time.Second, srv.HTTP2.PingTimeout)
			assert.Equal(t, 14*time.Second, srv.HTTP2.WriteByteTimeout)

			require.NotNil(t, srv.Protocols)
			assert.True(t, srv.Protocols.HTTP1())
			assert.Equal(t, tc.http2, srv.Protocols.HTTP2())
			assert.Equal(t, tc.unencryptedHTTP2, srv.Protocols.UnencryptedHTTP2())

			assert.NotNil(t, srv.ErrorLog)
			assert.Nil(t, srv.ConnContext)
		})
	}
}

func TestProxyService(t *testing.T) {
	t.Parallel()

	proxyKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	proxyCert, err := testsupport.NewCertificateBuilder(
		testsupport.WithSerialNumber(big.NewInt(1)),
		testsupport.WithValidity(time.Now(), 10*time.Hour),
		testsupport.WithSubject(pkix.Name{
			CommonName:   "test cert",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithSubjectPubKey(&proxyKey.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithSignaturePrivKey(proxyKey),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature),
		testsupport.WithExtendedKeyUsage(x509.ExtKeyUsageServerAuth),
		testsupport.WithGeneratedSubjectKeyID(),
		testsupport.WithIPAddresses([]net.IP{net.ParseIP("127.0.0.1")}),
		testsupport.WithSelfSigned(),
	).Build()
	require.NoError(t, err)

	for uc, tc := range map[string]struct {
		serviceConf    config.ServeConfig
		enableMetrics  bool
		disableHTTP2   bool
		upstreamScheme string
		createRequest  func(t *testing.T, host string) *http.Request
		createClient   func(t *testing.T) *http.Client
		configureMocks func(
			t *testing.T,
			exec *mocks2.ExecutorMock,
			target *mocks2.UpstreamTargetMock,
			sr *secretsmocks.ResolverMock,
			secretHandle *secretsmocks.SecretHandleMock,
			upstreamURL *url.URL,
		)
		processRequest func(t *testing.T, rw http.ResponseWriter, req *http.Request)
		assertResponse func(t *testing.T, err error, upstreamCalled bool, resp *http.Response)
	}{
		"no rules configured": {
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					t.Context(),
					http.MethodGet,
					fmt.Sprintf("http://%s/foobar", host),
					nil,
				)
				require.NoError(t, err)

				return req
			},
			configureMocks: func(
				t *testing.T,
				exec *mocks2.ExecutorMock,
				_ *mocks2.UpstreamTargetMock,
				_ *secretsmocks.ResolverMock,
				_ *secretsmocks.SecretHandleMock,
				_ *url.URL,
			) {
				t.Helper()

				exec.EXPECT().Execute(mock.Anything).Return(pipeline.ErrNoRuleFound)
			},
			assertResponse: func(t *testing.T, err error, upstreamCalled bool, resp *http.Response) {
				t.Helper()

				require.False(t, upstreamCalled)

				require.NoError(t, err)
				assert.Equal(t, http.StatusNotFound, resp.StatusCode)

				data, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Empty(t, data)
			},
		},
		"rule doesn't match method": {
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					t.Context(),
					http.MethodPost,
					fmt.Sprintf("http://%s/foobar", host),
					nil,
				)
				require.NoError(t, err)

				return req
			},
			configureMocks: func(
				t *testing.T,
				exec *mocks2.ExecutorMock,
				_ *mocks2.UpstreamTargetMock,
				_ *secretsmocks.ResolverMock,
				_ *secretsmocks.SecretHandleMock,
				_ *url.URL,
			) {
				t.Helper()

				exec.EXPECT().Execute(mock.Anything).Return(pipeline.ErrNoRuleFound)
			},
			assertResponse: func(t *testing.T, err error, upstreamCalled bool, resp *http.Response) {
				t.Helper()

				require.False(t, upstreamCalled)

				require.NoError(t, err)
				assert.Equal(t, http.StatusNotFound, resp.StatusCode)

				data, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Empty(t, data)
			},
		},
		"request finalization fails due to not configured upstream url": {
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					t.Context(),
					http.MethodPost,
					fmt.Sprintf("http://%s/foobar", host),
					nil,
				)
				require.NoError(t, err)

				return req
			},
			configureMocks: func(
				t *testing.T,
				exec *mocks2.ExecutorMock,
				_ *mocks2.UpstreamTargetMock,
				_ *secretsmocks.ResolverMock,
				_ *secretsmocks.SecretHandleMock,
				_ *url.URL,
			) {
				t.Helper()

				exec.EXPECT().Execute(mock.Anything).Return(nil)
			},
			assertResponse: func(t *testing.T, err error, upstreamCalled bool, resp *http.Response) {
				t.Helper()

				require.False(t, upstreamCalled)

				require.NoError(t, err)
				assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

				data, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Empty(t, data)
			},
		},
		"rule execution fails with authentication error": {
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					t.Context(),
					http.MethodPost,
					fmt.Sprintf("http://%s/foobar", host),
					nil,
				)
				require.NoError(t, err)

				return req
			},
			configureMocks: func(
				t *testing.T,
				exec *mocks2.ExecutorMock,
				_ *mocks2.UpstreamTargetMock,
				_ *secretsmocks.ResolverMock,
				_ *secretsmocks.SecretHandleMock,
				_ *url.URL,
			) {
				t.Helper()

				exec.EXPECT().Execute(mock.Anything).Return(pipeline.ErrAuthentication)
			},
			assertResponse: func(t *testing.T, err error, upstreamCalled bool, resp *http.Response) {
				t.Helper()

				require.False(t, upstreamCalled)

				require.NoError(t, err)
				assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

				data, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Empty(t, data)
			},
		},
		"rule execution fails with pipeline authorization error": {
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					t.Context(),
					http.MethodPost,
					fmt.Sprintf("http://%s/foobar", host),
					nil,
				)
				require.NoError(t, err)

				return req
			},
			configureMocks: func(
				t *testing.T,
				exec *mocks2.ExecutorMock,
				_ *mocks2.UpstreamTargetMock,
				_ *secretsmocks.ResolverMock,
				_ *secretsmocks.SecretHandleMock,
				_ *url.URL,
			) {
				t.Helper()

				exec.EXPECT().Execute(mock.Anything).Return(pipeline.ErrAuthorization)
			},
			assertResponse: func(t *testing.T, err error, upstreamCalled bool, resp *http.Response) {
				t.Helper()

				require.False(t, upstreamCalled)

				require.NoError(t, err)
				assert.Equal(t, http.StatusForbidden, resp.StatusCode)

				data, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Empty(t, data)
			},
		},
		"successful rule execution - request method and path are taken from the real request (trusted proxy not configured)": {
			upstreamScheme: "http",
			serviceConf: config.ServeConfig{
				Timeout: config.Timeout{Read: 1 * time.Second, Write: 1 * time.Second, Idle: 1 * time.Second},
			},
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					t.Context(),
					http.MethodPost,
					fmt.Sprintf("http://%s/foobar", host),
					strings.NewReader("hello"))
				require.NoError(t, err)

				req.Header.Set("Content-Type", "text/html")
				req.Header.Set("X-Forwarded-Method", http.MethodGet)
				req.Header.Set("X-Forwarded-Uri", "/barfoo")

				return req
			},
			configureMocks: func(
				t *testing.T,
				exec *mocks2.ExecutorMock,
				target *mocks2.UpstreamTargetMock,
				_ *secretsmocks.ResolverMock,
				_ *secretsmocks.SecretHandleMock,
				upstreamURL *url.URL,
			) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = url.URL{
						Scheme: upstreamURL.Scheme,
						Host:   upstreamURL.Host,
						Path:   "/foobar",
					}
				})
				target.EXPECT().ForwardHostHeader().Return(true)

				exec.EXPECT().Execute(
					mock.MatchedBy(func(ctx pipeline.ExecutionContext) bool {
						ctx.PrepareUpstreamView(target)
						ctx.UpstreamRequest().AddHeader("X-Foo-Bar", "baz")
						ctx.UpstreamRequest().SetCookie("X-Bar-Foo", "zab")

						pathMatched := ctx.Request().URL.Path == "/foobar"
						methodMatched := ctx.Request().Method == http.MethodPost

						return pathMatched && methodMatched
					}),
				).Return(nil)
			},
			processRequest: func(t *testing.T, rw http.ResponseWriter, req *http.Request) {
				t.Helper()

				assert.Equal(t, "HTTP/1.1", req.Proto)

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

				rw.Header().Set("Content-Type", "application/json")
				_, err = rw.Write([]byte(`{ "foo": "bar" }`))
				require.NoError(t, err)

				rw.WriteHeader(http.StatusOK)
			},
			assertResponse: func(t *testing.T, err error, upstreamCalled bool, resp *http.Response) {
				t.Helper()

				require.True(t, upstreamCalled)

				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, resp.StatusCode)

				assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

				data, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.JSONEq(t, `{ "foo": "bar" }`, string(data))
			},
		},
		"successful rule execution - headers are set": {
			disableHTTP2: true,
			serviceConf: config.ServeConfig{
				Timeout: config.Timeout{Read: 1 * time.Second, Write: 1 * time.Second, Idle: 1 * time.Second},
			},
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					t.Context(),
					http.MethodGet,
					fmt.Sprintf("http://%s/foobar", host),
					nil,
				)
				require.NoError(t, err)

				req.Header.Set("X-Foo-Bar", "bar")
				req.Header.Set("Te", "trailers")

				return req
			},
			configureMocks: func(
				t *testing.T,
				exec *mocks2.ExecutorMock,
				target *mocks2.UpstreamTargetMock,
				_ *secretsmocks.ResolverMock,
				_ *secretsmocks.SecretHandleMock,
				upstreamURL *url.URL,
			) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = url.URL{
						Scheme: upstreamURL.Scheme,
						Host:   upstreamURL.Host,
						Path:   "/bar",
					}
				})
				target.EXPECT().ForwardHostHeader().Return(true)

				exec.EXPECT().Execute(
					mock.MatchedBy(func(ctx pipeline.ExecutionContext) bool {
						ctx.PrepareUpstreamView(target)

						upstreamRequest := ctx.UpstreamRequest()
						upstreamRequest.SetHeader("X-Foo-Bar", "baz")
						upstreamRequest.SetHeader("X-Set", "foo")

						pathMatched := ctx.Request().URL.Path == "/foobar"
						methodMatched := ctx.Request().Method == http.MethodGet

						return pathMatched && methodMatched
					}),
				).Return(nil)
			},
			processRequest: func(t *testing.T, rw http.ResponseWriter, req *http.Request) {
				t.Helper()

				assert.Equal(t, http.MethodGet, req.Method)
				assert.Equal(t, "/bar", req.URL.Path)

				assert.Equal(t, "baz", req.Header.Get("X-Foo-Bar"))
				assert.Equal(t, "foo", req.Header.Get("X-Set"))
				assert.Equal(t, "trailers", req.Header.Get("Te"))

				rw.WriteHeader(http.StatusOK)
			},
			assertResponse: func(t *testing.T, err error, upstreamCalled bool, resp *http.Response) {
				t.Helper()

				require.True(t, upstreamCalled)

				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, resp.StatusCode)

				data, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Empty(t, data)
			},
		},
		"successful rule execution - request method is taken from the header (trusted proxy configured)": {
			serviceConf: config.ServeConfig{
				Timeout:        config.Timeout{Read: 1 * time.Second, Write: 1 * time.Second, Idle: 1 * time.Second},
				TrustedProxies: []string{"0.0.0.0/0"},
			},
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					t.Context(),
					http.MethodPost,
					"http://"+host+"/%5Bid%5D/foobar",
					strings.NewReader("hello"))
				require.NoError(t, err)

				req.Header.Set("Content-Type", "text/html")
				req.Header.Set("X-Forwarded-Method", http.MethodGet)

				return req
			},
			configureMocks: func(
				t *testing.T,
				exec *mocks2.ExecutorMock,
				target *mocks2.UpstreamTargetMock,
				_ *secretsmocks.ResolverMock,
				_ *secretsmocks.SecretHandleMock,
				upstreamURL *url.URL,
			) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = url.URL{
						Scheme: upstreamURL.Scheme,
						Host:   upstreamURL.Host,
						Path:   "/[id]/foobar",
					}
				})
				target.EXPECT().ForwardHostHeader().Return(true)

				exec.EXPECT().Execute(
					mock.MatchedBy(func(ctx pipeline.ExecutionContext) bool {
						ctx.PrepareUpstreamView(target)
						ctx.UpstreamRequest().AddHeader("X-Foo-Bar", "baz")
						ctx.UpstreamRequest().SetCookie("X-Bar-Foo", "zab")

						pathMatched := ctx.Request().URL.Path == "/[id]/foobar"
						methodMatched := ctx.Request().Method == http.MethodGet

						return pathMatched && methodMatched
					}),
				).Return(nil)
			},
			processRequest: func(t *testing.T, rw http.ResponseWriter, req *http.Request) {
				t.Helper()

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

				rw.Header().Set("Content-Type", "application/json")
				_, err = rw.Write([]byte(`{ "foo": "bar" }`))
				require.NoError(t, err)

				rw.WriteHeader(http.StatusOK)
			},
			assertResponse: func(t *testing.T, err error, upstreamCalled bool, resp *http.Response) {
				t.Helper()

				require.True(t, upstreamCalled)

				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, resp.StatusCode)

				assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

				data, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.JSONEq(t, `{ "foo": "bar" }`, string(data))
			},
		},
		"successful rule execution - request path is taken from the header (trusted proxy configured)": {
			serviceConf: config.ServeConfig{
				Timeout:        config.Timeout{Read: 1 * time.Second, Write: 1 * time.Second, Idle: 1 * time.Second},
				TrustedProxies: []string{"0.0.0.0/0"},
			},
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					t.Context(),
					http.MethodPost,
					fmt.Sprintf("http://%s/foobar", host),
					strings.NewReader("hello"))
				require.NoError(t, err)

				req.Header.Set("Content-Type", "text/html")
				req.Header.Set("X-Forwarded-Uri", "/%5Bbarfoo%5D")

				return req
			},
			configureMocks: func(
				t *testing.T,
				exec *mocks2.ExecutorMock,
				target *mocks2.UpstreamTargetMock,
				_ *secretsmocks.ResolverMock,
				_ *secretsmocks.SecretHandleMock,
				upstreamURL *url.URL,
			) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = url.URL{
						Scheme: upstreamURL.Scheme,
						Host:   upstreamURL.Host,
						Path:   "/[barfoo]",
					}
				})
				target.EXPECT().ForwardHostHeader().Return(true)

				exec.EXPECT().Execute(
					mock.MatchedBy(func(ctx pipeline.ExecutionContext) bool {
						ctx.PrepareUpstreamView(target)
						ctx.UpstreamRequest().AddHeader("X-Foo-Bar", "baz")
						ctx.UpstreamRequest().SetCookie("X-Bar-Foo", "zab")

						pathMatched := ctx.Request().URL.Path == "/[barfoo]"
						methodMatched := ctx.Request().Method == http.MethodPost

						return pathMatched && methodMatched
					}),
				).Return(nil)
			},
			processRequest: func(t *testing.T, rw http.ResponseWriter, req *http.Request) {
				t.Helper()

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

				rw.Header().Set("Content-Type", "application/json")
				_, err = rw.Write([]byte(`{ "foo": "bar" }`))
				require.NoError(t, err)

				rw.WriteHeader(http.StatusOK)
			},
			assertResponse: func(t *testing.T, err error, upstreamCalled bool, resp *http.Response) {
				t.Helper()

				require.True(t, upstreamCalled)

				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, resp.StatusCode)

				assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

				data, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.JSONEq(t, `{ "foo": "bar" }`, string(data))
			},
		},
		"CORS test actual request": {
			serviceConf: config.ServeConfig{
				Timeout: config.Timeout{Read: 1 * time.Second, Write: 1 * time.Second, Idle: 1 * time.Second},
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
					t.Context(),
					http.MethodGet,
					fmt.Sprintf("http://%s/foobar", host),
					strings.NewReader("hello"))
				require.NoError(t, err)

				req.Header.Set("Content-Type", "text/html")
				req.Header.Set("Origin", "https://foo.bar")

				return req
			},
			configureMocks: func(
				t *testing.T,
				exec *mocks2.ExecutorMock,
				target *mocks2.UpstreamTargetMock,
				_ *secretsmocks.ResolverMock,
				_ *secretsmocks.SecretHandleMock,
				upstreamURL *url.URL,
			) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = url.URL{
						Scheme: upstreamURL.Scheme,
						Host:   upstreamURL.Host,
						Path:   "/bar",
					}
				})
				target.EXPECT().ForwardHostHeader().Return(true)

				exec.EXPECT().Execute(
					mock.MatchedBy(func(ctx pipeline.ExecutionContext) bool {
						ctx.PrepareUpstreamView(target)
						ctx.UpstreamRequest().AddHeader("X-Foo-Bar", "baz")

						pathMatched := ctx.Request().URL.Path == "/foobar"
						methodMatched := ctx.Request().Method == http.MethodGet

						return pathMatched && methodMatched
					}),
				).Return(nil)
			},
			processRequest: func(t *testing.T, rw http.ResponseWriter, req *http.Request) {
				t.Helper()

				assert.Equal(t, http.MethodGet, req.Method)
				assert.Equal(t, "/bar", req.URL.Path)

				assert.Equal(t, "baz", req.Header.Get("X-Foo-Bar"))
				assert.Equal(t, "text/html", req.Header.Get("Content-Type"))

				data, err := io.ReadAll(req.Body)
				require.NoError(t, err)
				assert.Equal(t, "hello", string(data))

				rw.Header().Set("Content-Type", "application/json")
				_, err = rw.Write([]byte(`{ "foo": "bar" }`))
				require.NoError(t, err)

				rw.WriteHeader(http.StatusOK)
			},
			assertResponse: func(t *testing.T, err error, upstreamCalled bool, resp *http.Response) {
				t.Helper()

				require.True(t, upstreamCalled)

				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, resp.StatusCode)

				assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
				assert.Equal(t, "https://foo.bar", resp.Header.Get("Access-Control-Allow-Origin"))
				assert.Equal(t, "Origin", resp.Header.Get("Vary"))

				data, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.JSONEq(t, `{ "foo": "bar" }`, string(data))
			},
		},
		"CORS test preflight request": {
			serviceConf: config.ServeConfig{
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
					t.Context(),
					http.MethodOptions,
					fmt.Sprintf("http://%s/foobar", host),
					nil)
				require.NoError(t, err)

				req.Header.Set("Origin", "https://foo.bar")
				req.Header.Set("Access-Control-Request-Method", http.MethodGet)

				return req
			},
			configureMocks: func(
				t *testing.T,
				_ *mocks2.ExecutorMock,
				_ *mocks2.UpstreamTargetMock,
				_ *secretsmocks.ResolverMock,
				_ *secretsmocks.SecretHandleMock,
				_ *url.URL,
			) {
				t.Helper()
			},
			assertResponse: func(t *testing.T, err error, upstreamCalled bool, resp *http.Response) {
				t.Helper()

				require.False(t, upstreamCalled)

				require.NoError(t, err)
				assert.Equal(t, http.StatusNoContent, resp.StatusCode)

				assert.Equal(t, "https://foo.bar", resp.Header.Get("Access-Control-Allow-Origin"))
				assert.Equal(t, http.MethodGet, resp.Header.Get("Access-Control-Allow-Methods"))
				assert.NotEmpty(t, resp.Header["Vary"])
			},
		},
		"test metrics collection": {
			serviceConf: config.ServeConfig{
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
					t.Context(),
					http.MethodOptions,
					fmt.Sprintf("http://%s/foobar", host),
					nil)
				require.NoError(t, err)

				req.Header.Set("Origin", "https://foo.bar")
				req.Header.Set("Access-Control-Request-Method", http.MethodGet)

				return req
			},
			configureMocks: func(
				t *testing.T,
				_ *mocks2.ExecutorMock,
				_ *mocks2.UpstreamTargetMock,
				_ *secretsmocks.ResolverMock,
				_ *secretsmocks.SecretHandleMock,
				_ *url.URL,
			) {
				t.Helper()
			},
			assertResponse: func(t *testing.T, err error, upstreamCalled bool, resp *http.Response) {
				t.Helper()

				require.False(t, upstreamCalled)

				require.NoError(t, err)
				assert.Equal(t, http.StatusNoContent, resp.StatusCode)
			},
		},
		"http2 usage": {
			serviceConf: config.ServeConfig{
				Timeout: config.Timeout{Read: 1000 * time.Second, Write: 1000 * time.Second, Idle: 1000 * time.Second},
				TLS: &config.TLS{
					Secret: config.Secret{Source: "proxy", Selector: "server"},
				},
			},
			createClient: func(t *testing.T) *http.Client {
				t.Helper()

				pool := x509.NewCertPool()
				pool.AddCert(proxyCert)

				return &http.Client{
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{
							RootCAs:    pool,
							MinVersion: tls.VersionTLS13,
						},
						ForceAttemptHTTP2: true,
					},
				}
			},
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					t.Context(),
					http.MethodGet,
					fmt.Sprintf("https://%s/foobar", host),
					strings.NewReader("hello"))
				require.NoError(t, err)

				return req
			},
			configureMocks: func(
				t *testing.T,
				exec *mocks2.ExecutorMock,
				target *mocks2.UpstreamTargetMock,
				sr *secretsmocks.ResolverMock,
				secretHandle *secretsmocks.SecretHandleMock,
				upstreamURL *url.URL,
			) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = url.URL{
						Scheme: upstreamURL.Scheme,
						Host:   upstreamURL.Host,
						Path:   "/bar",
					}
				})
				target.EXPECT().ForwardHostHeader().Return(false)

				exec.EXPECT().Execute(
					mock.MatchedBy(func(ctx pipeline.ExecutionContext) bool {
						ctx.PrepareUpstreamView(target)
						ctx.UpstreamRequest().AddHeader("X-Foo-Bar", "baz")

						pathMatched := ctx.Request().URL.Path == "/foobar"
						methodMatched := ctx.Request().Method == http.MethodGet

						return pathMatched && methodMatched
					}),
				).Return(nil)

				secret := secrettypes.NewAsymmetricKeySecret(
					"server",
					"proxy",
					proxyKey,
					[]*x509.Certificate{proxyCert},
				)

				sr.EXPECT().
					Secret(secrets.Reference{Source: "proxy", Selector: "server"}).
					Return(secretHandle, nil)

				secretHandle.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Secret]) bool {
						err := cb(t.Context(), secret)
						require.NoError(t, err)

						return true
					}))
			},
			processRequest: func(t *testing.T, rw http.ResponseWriter, req *http.Request) {
				t.Helper()

				assert.Equal(t, "HTTP/2.0", req.Proto)

				assert.Equal(t, http.MethodGet, req.Method)
				assert.Equal(t, "/bar", req.URL.Path)

				assert.Equal(t, "baz", req.Header.Get("X-Foo-Bar"))

				data, err := io.ReadAll(req.Body)
				require.NoError(t, err)
				assert.Equal(t, "hello", string(data))

				rw.Header().Set("Content-Type", "application/json")
				_, err = rw.Write([]byte(`{ "foo": "bar" }`))
				require.NoError(t, err)

				rw.WriteHeader(http.StatusOK)
			},
			assertResponse: func(t *testing.T, err error, upstreamCalled bool, resp *http.Response) {
				t.Helper()

				require.NoError(t, err)
				require.True(t, upstreamCalled)

				assert.Equal(t, http.StatusOK, resp.StatusCode)

				assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

				data, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.JSONEq(t, `{ "foo": "bar" }`, string(data))
			},
		},
		"h2c usage": {
			upstreamScheme: "h2c",
			serviceConf: config.ServeConfig{
				Timeout: config.Timeout{Read: 1 * time.Second, Write: 1 * time.Second, Idle: 1 * time.Second},
			},
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					t.Context(),
					http.MethodGet,
					fmt.Sprintf("http://%s/foobar", host),
					nil,
				)
				require.NoError(t, err)

				return req
			},
			configureMocks: func(
				t *testing.T,
				exec *mocks2.ExecutorMock,
				target *mocks2.UpstreamTargetMock,
				_ *secretsmocks.ResolverMock,
				_ *secretsmocks.SecretHandleMock,
				upstreamURL *url.URL,
			) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = url.URL{
						Scheme: upstreamURL.Scheme,
						Host:   upstreamURL.Host,
						Path:   "/bar",
					}
				})
				target.EXPECT().ForwardHostHeader().Return(true)

				exec.EXPECT().Execute(mock.Anything).Run(func(ctx pipeline.ExecutionContext) {
					ctx.PrepareUpstreamView(target)
				}).Return(nil)
			},
			processRequest: func(t *testing.T, rw http.ResponseWriter, req *http.Request) {
				t.Helper()

				assert.Equal(t, "HTTP/2.0", req.Proto)
				assert.Equal(t, "/bar", req.URL.Path)

				rw.WriteHeader(http.StatusOK)
			},
			assertResponse: func(t *testing.T, err error, upstreamCalled bool, resp *http.Response) {
				t.Helper()

				require.NoError(t, err)
				require.True(t, upstreamCalled)
				require.NotNil(t, resp)

				assert.Equal(t, http.StatusOK, resp.StatusCode)
			},
		},
		"native gRPC uses http2 over https": {
			serviceConf: config.ServeConfig{
				Timeout: config.Timeout{Read: 1 * time.Second, Write: 1 * time.Second, Idle: 1 * time.Second},
			},
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					t.Context(),
					http.MethodPost,
					fmt.Sprintf("http://%s/foobar", host),
					nil,
				)
				require.NoError(t, err)

				req.Header.Set("Content-Type", grpcContentType)

				return req
			},
			configureMocks: func(
				t *testing.T,
				exec *mocks2.ExecutorMock,
				target *mocks2.UpstreamTargetMock,
				_ *secretsmocks.ResolverMock,
				_ *secretsmocks.SecretHandleMock,
				upstreamURL *url.URL,
			) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = url.URL{
						Scheme: upstreamURL.Scheme,
						Host:   upstreamURL.Host,
						Path:   "/bar",
					}
				})
				target.EXPECT().ForwardHostHeader().Return(true)

				exec.EXPECT().Execute(mock.Anything).Run(func(ctx pipeline.ExecutionContext) {
					ctx.PrepareUpstreamView(target)
				}).Return(nil)
			},
			processRequest: func(t *testing.T, rw http.ResponseWriter, req *http.Request) {
				t.Helper()

				assert.Equal(t, "HTTP/2.0", req.Proto)
				assert.Equal(t, grpcContentType, req.Header.Get("Content-Type"))

				rw.WriteHeader(http.StatusOK)
			},
			assertResponse: func(t *testing.T, err error, upstreamCalled bool, resp *http.Response) {
				t.Helper()

				require.NoError(t, err)
				require.True(t, upstreamCalled)
				require.NotNil(t, resp)

				assert.Equal(t, http.StatusOK, resp.StatusCode)
			},
		},
		"native gRPC uses h2c": {
			upstreamScheme: "h2c",
			serviceConf: config.ServeConfig{
				Timeout: config.Timeout{Read: 1 * time.Second, Write: 1 * time.Second, Idle: 1 * time.Second},
			},
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					t.Context(),
					http.MethodPost,
					fmt.Sprintf("http://%s/foobar", host),
					nil,
				)
				require.NoError(t, err)

				req.Header.Set("Content-Type", grpcContentType)

				return req
			},
			configureMocks: func(
				t *testing.T,
				exec *mocks2.ExecutorMock,
				target *mocks2.UpstreamTargetMock,
				_ *secretsmocks.ResolverMock,
				_ *secretsmocks.SecretHandleMock,
				upstreamURL *url.URL,
			) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = url.URL{
						Scheme: upstreamURL.Scheme,
						Host:   upstreamURL.Host,
						Path:   "/bar",
					}
				})
				target.EXPECT().ForwardHostHeader().Return(true)

				exec.EXPECT().Execute(mock.Anything).Run(func(ctx pipeline.ExecutionContext) {
					ctx.PrepareUpstreamView(target)
				}).Return(nil)
			},
			processRequest: func(t *testing.T, rw http.ResponseWriter, req *http.Request) {
				t.Helper()

				assert.Equal(t, "HTTP/2.0", req.Proto)
				assert.Equal(t, grpcContentType, req.Header.Get("Content-Type"))

				rw.WriteHeader(http.StatusOK)
			},
			assertResponse: func(t *testing.T, err error, upstreamCalled bool, resp *http.Response) {
				t.Helper()

				require.NoError(t, err)
				require.True(t, upstreamCalled)
				require.NotNil(t, resp)

				assert.Equal(t, http.StatusOK, resp.StatusCode)
			},
		},
		"native gRPC over http is rejected": {
			upstreamScheme: "http",
			serviceConf: config.ServeConfig{
				Timeout: config.Timeout{Read: 1 * time.Second, Write: 1 * time.Second, Idle: 1 * time.Second},
			},
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					t.Context(),
					http.MethodPost,
					fmt.Sprintf("http://%s/foobar", host),
					nil,
				)
				require.NoError(t, err)

				req.Header.Set("Content-Type", grpcContentType)

				return req
			},
			configureMocks: func(
				t *testing.T,
				exec *mocks2.ExecutorMock,
				target *mocks2.UpstreamTargetMock,
				_ *secretsmocks.ResolverMock,
				_ *secretsmocks.SecretHandleMock,
				upstreamURL *url.URL,
			) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = url.URL{
						Scheme: upstreamURL.Scheme,
						Host:   upstreamURL.Host,
						Path:   "/bar",
					}
				})
				target.EXPECT().ForwardHostHeader().Return(true)

				exec.EXPECT().Execute(mock.Anything).Run(func(ctx pipeline.ExecutionContext) {
					ctx.PrepareUpstreamView(target)
				}).Return(nil)
			},
			assertResponse: func(t *testing.T, err error, upstreamCalled bool, resp *http.Response) {
				t.Helper()

				require.NoError(t, err)
				require.False(t, upstreamCalled)
				require.NotNil(t, resp)

				assert.Equal(t, http.StatusBadGateway, resp.StatusCode)

				data, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Empty(t, data)
			},
		},
		"upgrade over h2c is rejected": {
			upstreamScheme: "h2c",
			serviceConf: config.ServeConfig{
				Timeout: config.Timeout{Read: 1 * time.Second, Write: 1 * time.Second, Idle: 1 * time.Second},
			},
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					t.Context(),
					http.MethodGet,
					fmt.Sprintf("http://%s/foobar", host),
					nil,
				)
				require.NoError(t, err)

				req.Header.Set("Connection", "Upgrade")
				req.Header.Set("Upgrade", "websocket")

				return req
			},
			configureMocks: func(
				t *testing.T,
				exec *mocks2.ExecutorMock,
				target *mocks2.UpstreamTargetMock,
				_ *secretsmocks.ResolverMock,
				_ *secretsmocks.SecretHandleMock,
				upstreamURL *url.URL,
			) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = url.URL{
						Scheme: upstreamURL.Scheme,
						Host:   upstreamURL.Host,
						Path:   "/bar",
					}
				})
				target.EXPECT().ForwardHostHeader().Return(true)

				exec.EXPECT().Execute(mock.Anything).Run(func(ctx pipeline.ExecutionContext) {
					ctx.PrepareUpstreamView(target)
				}).Return(nil)
			},
			assertResponse: func(t *testing.T, err error, upstreamCalled bool, resp *http.Response) {
				t.Helper()

				require.NoError(t, err)
				require.False(t, upstreamCalled)
				require.NotNil(t, resp)

				assert.Equal(t, http.StatusBadGateway, resp.StatusCode)

				data, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Empty(t, data)
			},
		},
		"http2 not supported by upstream server": {
			disableHTTP2: true,
			serviceConf: config.ServeConfig{
				Timeout: config.Timeout{Read: 1 * time.Second, Write: 1 * time.Second, Idle: 1 * time.Second},
				TLS: &config.TLS{
					Secret: config.Secret{Source: "proxy", Selector: "server"},
				},
			},
			createClient: func(t *testing.T) *http.Client {
				t.Helper()

				pool := x509.NewCertPool()
				pool.AddCert(proxyCert)

				return &http.Client{
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{
							RootCAs:    pool,
							MinVersion: tls.VersionTLS13,
						},
						ForceAttemptHTTP2: true,
					},
				}
			},
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					t.Context(),
					http.MethodGet,
					fmt.Sprintf("https://%s/foobar", host),
					strings.NewReader("hello"))
				require.NoError(t, err)

				return req
			},
			configureMocks: func(
				t *testing.T,
				exec *mocks2.ExecutorMock,
				target *mocks2.UpstreamTargetMock,
				sr *secretsmocks.ResolverMock,
				secretHandle *secretsmocks.SecretHandleMock,
				upstreamURL *url.URL,
			) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = url.URL{
						Scheme: upstreamURL.Scheme,
						Host:   upstreamURL.Host,
						Path:   "/bar",
					}
				})
				target.EXPECT().ForwardHostHeader().Return(true)

				exec.EXPECT().Execute(
					mock.MatchedBy(func(ctx pipeline.ExecutionContext) bool {
						ctx.PrepareUpstreamView(target)
						ctx.UpstreamRequest().AddHeader("X-Foo-Bar", "baz")

						pathMatched := ctx.Request().URL.Path == "/foobar"
						methodMatched := ctx.Request().Method == http.MethodGet

						return pathMatched && methodMatched
					}),
				).Return(nil)

				secret := secrettypes.NewAsymmetricKeySecret(
					"server",
					"proxy",
					proxyKey,
					[]*x509.Certificate{proxyCert},
				)

				sr.EXPECT().
					Secret(secrets.Reference{Source: "proxy", Selector: "server"}).
					Return(secretHandle, nil)

				secretHandle.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Secret]) bool {
						err := cb(t.Context(), secret)
						require.NoError(t, err)

						return true
					}))
			},
			processRequest: func(t *testing.T, rw http.ResponseWriter, req *http.Request) {
				t.Helper()

				assert.Equal(t, "HTTP/1.1", req.Proto)

				assert.Equal(t, http.MethodGet, req.Method)
				assert.Equal(t, "/bar", req.URL.Path)

				assert.Equal(t, "baz", req.Header.Get("X-Foo-Bar"))

				data, err := io.ReadAll(req.Body)
				require.NoError(t, err)
				assert.Equal(t, "hello", string(data))

				rw.Header().Set("Content-Type", "application/json")
				_, err = rw.Write([]byte(`{ "foo": "bar" }`))
				require.NoError(t, err)

				rw.WriteHeader(http.StatusOK)
			},
			assertResponse: func(t *testing.T, err error, upstreamCalled bool, resp *http.Response) {
				t.Helper()

				require.NoError(t, err)
				require.True(t, upstreamCalled)

				assert.Equal(t, http.StatusOK, resp.StatusCode)

				assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

				data, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.JSONEq(t, `{ "foo": "bar" }`, string(data))
			},
		},
		"native gRPC does not fall back to http1": {
			disableHTTP2: true,
			serviceConf: config.ServeConfig{
				Timeout: config.Timeout{Read: 1 * time.Second, Write: 1 * time.Second, Idle: 1 * time.Second},
			},
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					t.Context(),
					http.MethodPost,
					fmt.Sprintf("http://%s/foobar", host),
					nil,
				)
				require.NoError(t, err)

				req.Header.Set("Content-Type", grpcContentType)

				return req
			},
			configureMocks: func(
				t *testing.T,
				exec *mocks2.ExecutorMock,
				target *mocks2.UpstreamTargetMock,
				_ *secretsmocks.ResolverMock,
				_ *secretsmocks.SecretHandleMock,
				upstreamURL *url.URL,
			) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = url.URL{
						Scheme: upstreamURL.Scheme,
						Host:   upstreamURL.Host,
						Path:   "/bar",
					}
				})
				target.EXPECT().ForwardHostHeader().Return(true)

				exec.EXPECT().Execute(mock.Anything).Run(func(ctx pipeline.ExecutionContext) {
					ctx.PrepareUpstreamView(target)
				}).Return(nil)
			},
			assertResponse: func(t *testing.T, err error, upstreamCalled bool, resp *http.Response) {
				t.Helper()

				require.NoError(t, err)
				require.False(t, upstreamCalled)
				require.NotNil(t, resp)

				assert.Equal(t, http.StatusBadGateway, resp.StatusCode)

				data, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Empty(t, data)
			},
		},
		"request body exceeds limit with known content length": {
			serviceConf: config.ServeConfig{
				Requests: config.IngressRequests{
					Body: config.IngressRequestBody{
						MaxSize: 5 * bytesize.B,
					},
				},
			},
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					t.Context(),
					http.MethodPost,
					fmt.Sprintf("http://%s/foobar", host),
					strings.NewReader("123456"),
				)
				require.NoError(t, err)

				return req
			},
			configureMocks: func(
				t *testing.T,
				_ *mocks2.ExecutorMock,
				_ *mocks2.UpstreamTargetMock,
				_ *secretsmocks.ResolverMock,
				_ *secretsmocks.SecretHandleMock,
				_ *url.URL,
			) {
				t.Helper()
			},
			assertResponse: func(t *testing.T, err error, upstreamCalled bool, resp *http.Response) {
				t.Helper()

				require.NoError(t, err)
				require.False(t, upstreamCalled)
				require.NotNil(t, resp)

				assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)

				data, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Empty(t, data)
			},
		},
		"request with unknown length exceeds body limit": {
			serviceConf: config.ServeConfig{
				Requests: config.IngressRequests{
					Body: config.IngressRequestBody{
						MaxSize: 5 * bytesize.B,
					},
				},
			},
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					t.Context(),
					http.MethodPost,
					fmt.Sprintf("http://%s/foobar", host),
					strings.NewReader("123456"),
				)
				require.NoError(t, err)

				// Force streaming/chunked semantics so the bodylimit middleware
				// cannot reject the request based on Content-Length.
				req.ContentLength = -1

				return req
			},
			configureMocks: func(
				t *testing.T,
				exec *mocks2.ExecutorMock,
				target *mocks2.UpstreamTargetMock,
				_ *secretsmocks.ResolverMock,
				_ *secretsmocks.SecretHandleMock,
				upstreamURL *url.URL,
			) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = url.URL{
						Scheme: upstreamURL.Scheme,
						Host:   upstreamURL.Host,
						Path:   "/foobar",
					}
				})
				target.EXPECT().ForwardHostHeader().Return(true)

				exec.EXPECT().Execute(
					mock.MatchedBy(func(ctx pipeline.ExecutionContext) bool {
						// Deliberately do not access Body()/RawBody().
						// The request must reach the proxy path before its
						// unknown-length body can exceed the limit.
						ctx.PrepareUpstreamView(target)

						return true
					}),
				).Return(nil)
			},
			processRequest: func(t *testing.T, _ http.ResponseWriter, req *http.Request) {
				t.Helper()

				// If the upstream handler is reached, consume the streamed body.
				// Whether the handler itself is reached is transport timing dependent.
				_, _ = io.Copy(io.Discard, req.Body)
			},
			assertResponse: func(t *testing.T, err error, _ bool, resp *http.Response) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, resp)

				assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)

				data, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Empty(t, data)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			exp := metric.NewManualReader()

			if tc.enableMetrics {
				otel.SetMeterProvider(metric.NewMeterProvider(
					metric.WithResource(resource.Default()),
					metric.WithReader(exp),
				))
			}

			var upstreamCalled atomic.Bool

			processRequest := x.IfThenElse(tc.processRequest != nil, tc.processRequest,
				func(t *testing.T, rw http.ResponseWriter, _ *http.Request) {
					t.Helper()

					rw.WriteHeader(http.StatusOK)
				})

			upstreamSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamCalled.Store(true)

				processRequest(t, w, r)
			}))
			defer upstreamSrv.Close()

			switch tc.upstreamScheme {
			case "http":
				upstreamSrv.Start()
			case "h2c":
				upstreamSrv.Config.Protocols = new(http.Protocols)
				upstreamSrv.Config.Protocols.SetUnencryptedHTTP2(true)
				upstreamSrv.Start()
			default:
				upstreamSrv.EnableHTTP2 = !tc.disableHTTP2
				upstreamSrv.StartTLS()

				certPool := x509.NewCertPool()
				certPool.AddCert(upstreamSrv.Certificate())
				tlsClientConfig = &tls.Config{RootCAs: certPool} //nolint:gosec
			}

			upstreamURL, err := url.Parse(upstreamSrv.URL)
			require.NoError(t, err)

			if tc.upstreamScheme == "h2c" {
				upstreamURL.Scheme = "h2c"
			}

			createClient := x.IfThenElse(tc.createClient != nil,
				tc.createClient,
				func(t *testing.T) *http.Client {
					t.Helper()

					return &http.Client{Transport: &http.Transport{}}
				})

			port, err := testsupport.GetFreePort()
			require.NoError(t, err)

			proxyConf := tc.serviceConf
			proxyConf.Host = "127.0.0.1"
			proxyConf.Port = port

			conf := &config.Configuration{
				Serve:   proxyConf,
				Metrics: config.MetricsConfig{Enabled: tc.enableMetrics},
			}
			cch := mocks.NewCacheMock(t)
			exec := mocks2.NewExecutorMock(t)
			target := mocks2.NewUpstreamTargetMock(t)
			sr := secretsmocks.NewResolverMock(t)
			secretHandle := secretsmocks.NewSecretHandleMock(t)

			tc.configureMocks(t, exec, target, sr, secretHandle, upstreamURL)

			factory, err := listener.NewFactory(
				proxyConf.Address(),
				proxyConf.TLS,
				0,
				sr,
			)
			require.NoError(t, err)

			lstnr, err := factory.Create(t.Context())
			require.NoError(t, err)

			client := createClient(t)

			proxy := newService(conf, cch, log.Logger, exec)

			defer proxy.Shutdown(t.Context())

			go func() {
				_ = proxy.Serve(lstnr)
			}()

			time.Sleep(50 * time.Millisecond)

			// WHEN
			resp, err := client.Do(tc.createRequest(t, proxyConf.Address()))

			// THEN
			if err == nil {
				defer resp.Body.Close()
			}

			tc.assertResponse(t, err, upstreamCalled.Load(), resp)

			var rm metricdata.ResourceMetrics

			err = exp.Collect(t.Context(), &rm)

			if tc.enableMetrics {
				require.NoError(t, err)
				require.NotEmpty(t, rm.ScopeMetrics)
			} else {
				require.Empty(t, rm.ScopeMetrics)
			}
		})
	}

	t.Run("rejects request if maximum number of requests is in flight", func(t *testing.T) {
		// GIVEN
		port, err := testsupport.GetFreePort()
		require.NoError(t, err)

		proxyConf := config.ServeConfig{
			Host: "127.0.0.1",
			Port: port,
		}

		proxyConf.Requests.MaxInFlight = 1
		proxyConf.Respond.With.TooManyRequests.Code = http.StatusServiceUnavailable

		factory, err := listener.NewFactory(proxyConf.Address(), proxyConf.TLS, 0, nil)
		require.NoError(t, err)

		lstnr, err := factory.Create(t.Context())
		require.NoError(t, err)

		conf := &config.Configuration{Serve: proxyConf}
		exec := mocks2.NewExecutorMock(t)

		requestEntered := make(chan struct{}, 2)
		releaseRequest := make(chan struct{})

		var releaseOnce sync.Once
		release := func() {
			releaseOnce.Do(func() {
				close(releaseRequest)
			})
		}

		exec.EXPECT().Execute(mock.Anything).
			Run(func(_ pipeline.ExecutionContext) {
				requestEntered <- struct{}{}

				<-releaseRequest
			}).
			Return(pipeline.ErrNoRuleFound)

		proxy := newService(conf, mocks.NewCacheMock(t), log.Logger, exec)

		defer func() {
			release()
			_ = proxy.Shutdown(t.Context())
		}()

		go func() {
			_ = proxy.Serve(lstnr)
		}()

		time.Sleep(50 * time.Millisecond)

		client := &http.Client{Transport: &http.Transport{}}

		firstResponse := make(chan *http.Response, 1)
		firstError := make(chan error, 1)

		go func() {
			req, err := http.NewRequestWithContext(
				t.Context(),
				http.MethodGet,
				fmt.Sprintf("http://%s/", proxyConf.Address()),
				nil,
			)
			if err != nil {
				firstError <- err

				return
			}

			resp, err := client.Do(req) //nolint:bodyclose
			firstResponse <- resp
			firstError <- err
		}()

		select {
		case <-requestEntered:
		case <-time.After(time.Second):
			require.FailNow(t, "first request did not enter pipeline")
		}

		secondRequest, err := http.NewRequestWithContext(
			t.Context(),
			http.MethodGet,
			fmt.Sprintf("http://%s/", proxyConf.Address()),
			nil,
		)
		require.NoError(t, err)

		var (
			secondResponse *http.Response
			secondErr      error
		)

		secondDone := make(chan struct{})

		// WHEN
		go func() {
			defer close(secondDone)

			secondResponse, secondErr = client.Do(secondRequest) //nolint:bodyclose
		}()

		// THEN
		select {
		case <-requestEntered:
			require.FailNow(t, "second request entered pipeline while maximum number of requests was in flight")

		case <-secondDone:
			require.NoError(t, secondErr)
			require.NotNil(t, secondResponse)
			defer secondResponse.Body.Close()

			assert.Equal(t, http.StatusServiceUnavailable, secondResponse.StatusCode)

			data, err := io.ReadAll(secondResponse.Body)
			require.NoError(t, err)
			assert.Empty(t, data)

		case <-time.After(time.Second):
			require.FailNow(t, "second request was not rejected immediately")
		}

		// WHEN
		release()

		// THEN
		select {
		case err := <-firstError:
			require.NoError(t, err)
		case <-time.After(time.Second):
			require.FailNow(t, "first request did not complete")
		}

		select {
		case resp := <-firstResponse:
			require.NotNil(t, resp)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		case <-time.After(time.Second):
			require.FailNow(t, "first response was not received")
		}
	})

	t.Run("applies request body read idle timeout", func(t *testing.T) {
		// GIVEN
		port, err := testsupport.GetFreePort()
		require.NoError(t, err)

		bodyReadResult := make(chan error, 1)
		exec := testExecutor(func(ctx pipeline.ExecutionContext) error {
			_, err := ctx.Request().Body()
			bodyReadResult <- err

			return err
		})
		conf := &config.Configuration{
			Serve: config.ServeConfig{
				Host: "127.0.0.1",
				Port: port,
				Requests: config.IngressRequests{
					Body: config.IngressRequestBody{
						ReadIdleTimeout: 100 * time.Millisecond,
					},
				},
			},
		}

		factory, err := listener.NewFactory(
			conf.Serve.Address(),
			conf.Serve.TLS,
			0,
			nil,
		)
		require.NoError(t, err)

		lstnr, err := factory.Create(t.Context())
		require.NoError(t, err)

		proxy := newService(conf, mocks.NewCacheMock(t), log.Logger, exec)
		defer proxy.Shutdown(t.Context())

		go func() {
			_ = proxy.Serve(lstnr)
		}()

		time.Sleep(50 * time.Millisecond)

		dialer := &net.Dialer{}
		conn, err := dialer.DialContext(t.Context(), "tcp", conf.Serve.Address())
		require.NoError(t, err)
		defer conn.Close()

		_, err = io.WriteString(
			conn,
			"POST / HTTP/1.1\r\nHost: "+conf.Serve.Address()+"\r\nContent-Length: 1\r\n\r\n",
		)
		require.NoError(t, err)

		// WHEN
		var bodyReadErr error
		select {
		case bodyReadErr = <-bodyReadResult:
		case <-time.After(2 * time.Second):
			require.FailNow(t, "request body read did not complete")
		}

		// THEN
		require.Error(t, bodyReadErr)

		var netErr net.Error
		require.ErrorAs(t, bodyReadErr, &netErr)
		assert.True(t, netErr.Timeout())
	})
}

func TestProxyServiceUsesUpdatedUpstreamScheme(t *testing.T) {
	// GIVEN
	upstreamProtocols := make(chan string, 2)
	upstreamSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		upstreamProtocols <- req.Proto

		rw.WriteHeader(http.StatusOK)
	}))
	defer upstreamSrv.Close()

	upstreamSrv.Config.Protocols = new(http.Protocols)
	upstreamSrv.Config.Protocols.SetHTTP1(true)
	upstreamSrv.Config.Protocols.SetUnencryptedHTTP2(true)
	upstreamSrv.Start()

	upstreamURL, err := url.Parse(upstreamSrv.URL)
	require.NoError(t, err)

	var (
		schemeMu sync.RWMutex
		scheme   = "http"
	)

	target := mocks2.NewUpstreamTargetMock(t)
	target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
		schemeMu.RLock()
		defer schemeMu.RUnlock()

		*targetURL = url.URL{
			Scheme: scheme,
			Host:   upstreamURL.Host,
			Path:   "/bar",
		}
	}).Twice()
	target.EXPECT().ForwardHostHeader().Return(true).Twice()

	exec := mocks2.NewExecutorMock(t)
	exec.EXPECT().Execute(mock.Anything).Run(func(ctx pipeline.ExecutionContext) {
		ctx.PrepareUpstreamView(target)
	}).Return(nil).Twice()

	port, err := testsupport.GetFreePort()
	require.NoError(t, err)

	conf := &config.Configuration{
		Serve: config.ServeConfig{
			Host: "127.0.0.1",
			Port: port,
			Timeout: config.Timeout{
				Read:  1 * time.Second,
				Write: 1 * time.Second,
				Idle:  1 * time.Second,
			},
		},
	}

	factory, err := listener.NewFactory(
		conf.Serve.Address(),
		conf.Serve.TLS,
		0,
		nil,
	)
	require.NoError(t, err)

	lstnr, err := factory.Create(t.Context())
	require.NoError(t, err)

	proxy := newService(conf, mocks.NewCacheMock(t), log.Logger, exec)
	defer proxy.Shutdown(t.Context())

	go func() {
		_ = proxy.Serve(lstnr)
	}()

	time.Sleep(50 * time.Millisecond)

	client := &http.Client{Transport: &http.Transport{}}

	doRequest := func() *http.Response {
		req, err := http.NewRequestWithContext(
			t.Context(),
			http.MethodGet,
			fmt.Sprintf("http://%s/foo", conf.Serve.Address()),
			nil,
		)
		require.NoError(t, err)

		resp, err := client.Do(req) //nolint:bodyclose
		require.NoError(t, err)
		require.NotNil(t, resp)

		return resp
	}

	// WHEN
	resp := doRequest()

	// THEN
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, "HTTP/1.1", <-upstreamProtocols)

	// WHEN
	schemeMu.Lock()
	scheme = "h2c"
	schemeMu.Unlock()

	resp = doRequest()

	// THEN
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, "HTTP/2.0", <-upstreamProtocols)
}

func TestWebSocketSupport(t *testing.T) {
	t.Parallel()

	port, err := testsupport.GetFreePort()
	require.NoError(t, err)

	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		assert.Equal(t, "HTTP/1.1", req.Proto)
		assert.Equal(t, "/bar", req.URL.Path)

		upgrader := websocket.Upgrader{
			CheckOrigin: func(_ *http.Request) bool {
				return true
			},
		}

		con, err := upgrader.Upgrade(rw, req, nil)
		assert.NoError(t, err)

		defer con.Close()

		err = con.WriteMessage(websocket.TextMessage, []byte("ping 1"))
		assert.NoError(t, err)

		_, message, err := con.ReadMessage()
		assert.NoError(t, err)
		assert.Equal(t, []byte("ping 1"), message)

		// The HTTP response write policy ends at a successful hijack. A quiet
		// tunnel must therefore remain usable even after the configured response
		// write-idle window has elapsed.
		time.Sleep(150 * time.Millisecond)

		err = con.WriteMessage(websocket.TextMessage, []byte("ping 2"))
		assert.NoError(t, err)

		_, message, err = con.ReadMessage()
		assert.NoError(t, err)
		assert.Equal(t, []byte("ping 2"), message)
	}))
	defer upstreamSrv.Close()

	upstreamURL, err := url.Parse(upstreamSrv.URL)
	require.NoError(t, err)

	target := testUpstreamTarget{
		targetURL: url.URL{
			Scheme: upstreamURL.Scheme,
			Host:   upstreamURL.Host,
			Path:   "/bar",
		},
		forwardHostHeader: true,
	}
	exec := testExecutor(func(ctx pipeline.ExecutionContext) error {
		assert.Equal(t, "/foo", ctx.Request().URL.Path)
		assert.Equal(t, http.MethodGet, ctx.Request().Method)

		ctx.PrepareUpstreamView(target)

		return nil
	})

	conf := &config.Configuration{
		Serve: config.ServeConfig{
			Host: "127.0.0.1",
			Port: port,
			Responses: config.IngressResponses{
				WriteIdleTimeout: 50 * time.Millisecond,
				WriteMinRate:     500,
			},
		},
	}

	traceLogger := zerolog.New(io.Discard).Level(zerolog.TraceLevel)
	proxy := newService(conf, mocks.NewCacheMock(t), traceLogger, exec)

	defer proxy.Shutdown(t.Context())

	factory, err := listener.NewFactory(
		conf.Serve.Address(),
		conf.Serve.TLS,
		0,
		nil,
	)
	require.NoError(t, err)

	lstnr, err := factory.Create(t.Context())
	require.NoError(t, err)

	go func() {
		_ = proxy.Serve(lstnr)
	}()

	time.Sleep(50 * time.Millisecond)

	wsURL := url.URL{Scheme: "ws", Host: conf.Serve.Address(), Path: "/foo"}
	con, resp, err := websocket.DefaultDialer.Dial(wsURL.String(), nil)
	require.NoError(t, err)

	defer resp.Body.Close()
	defer con.Close()

	mt, message, err := con.ReadMessage()
	require.NoError(t, err)
	require.Equal(t, websocket.TextMessage, mt)
	assert.Equal(t, []byte("ping 1"), message)

	err = con.WriteMessage(mt, message)
	require.NoError(t, err)

	mt, message, err = con.ReadMessage()
	require.NoError(t, err)
	require.Equal(t, websocket.TextMessage, mt)
	assert.Equal(t, []byte("ping 2"), message)

	err = con.WriteMessage(websocket.TextMessage, message)
	require.NoError(t, err)

	err = con.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	require.NoError(t, err)
}

func TestServerSentEventsSupport(t *testing.T) {
	t.Parallel()

	port, err := testsupport.GetFreePort()
	require.NoError(t, err)

	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		assert.Equal(t, "/bar", req.URL.Path)

		rw.Header().Set("Content-Type", "text/event-stream")
		rw.Header().Set("Cache-Control", "no-cache")
		rw.Header().Set("Connection", "keep-alive")

		rc := http.NewResponseController(rw) //nolint:bodyclose

		for i := range 5 {
			_, err := rw.Write(stringx.ToBytes(strconv.Itoa(i)))
			assert.NoError(t, err)

			assert.NoError(t, rc.Flush())

			if i == 1 {
				// A stream may be legitimately silent for longer than the response
				// write-idle timeout when no write is in flight.
				time.Sleep(150 * time.Millisecond)
			} else {
				time.Sleep(20 * time.Millisecond)
			}
		}
	}))
	defer upstreamSrv.Close()

	upstreamURL, err := url.Parse(upstreamSrv.URL)
	require.NoError(t, err)

	target := testUpstreamTarget{
		targetURL: url.URL{
			Scheme: upstreamURL.Scheme,
			Host:   upstreamURL.Host,
			Path:   "/bar",
		},
		forwardHostHeader: true,
	}
	exec := testExecutor(func(ctx pipeline.ExecutionContext) error {
		assert.Equal(t, "/foo", ctx.Request().URL.Path)
		assert.Equal(t, http.MethodGet, ctx.Request().Method)

		ctx.PrepareUpstreamView(target)

		return nil
	})

	conf := &config.Configuration{
		Serve: config.ServeConfig{
			Host: "127.0.0.1",
			Port: port,
			Responses: config.IngressResponses{
				WriteIdleTimeout: 50 * time.Millisecond,
				WriteMinRate:     0,
			},
		},
	}

	proxy := newService(conf, mocks.NewCacheMock(t), log.Logger, exec)

	defer proxy.Shutdown(t.Context())

	factory, err := listener.NewFactory(
		conf.Serve.Address(),
		conf.Serve.TLS,
		0,
		nil,
	)
	require.NoError(t, err)

	lstnr, err := factory.Create(t.Context())
	require.NoError(t, err)

	go func() {
		_ = proxy.Serve(lstnr)
	}()

	time.Sleep(50 * time.Millisecond)

	req, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		fmt.Sprintf("http://%s/foo", conf.Serve.Address()),
		nil,
	)
	require.NoError(t, err)
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Connection", "keep-alive")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	data := make([]byte, 1)

	for i := range 5 {
		_, err = resp.Body.Read(data)
		require.NoError(t, err)
		val, err := strconv.Atoi(stringx.ToString(data))
		require.NoError(t, err)
		assert.Equal(t, i, val)
	}
}
