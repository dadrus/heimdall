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
	"context"
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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
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
	"github.com/dadrus/heimdall/internal/heimdall"
	mocks4 "github.com/dadrus/heimdall/internal/rules/rule/mocks"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/pkix/pemx"
	"github.com/dadrus/heimdall/internal/x/stringx"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestProxyService(t *testing.T) {
	t.Parallel()

	testDir := t.TempDir()

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

	pemBytes, err := pemx.BuildPEM(
		pemx.WithECDSAPrivateKey(proxyKey),
		pemx.WithX509Certificate(proxyCert),
	)
	require.NoError(t, err)

	pemFile, err := os.Create(filepath.Join(testDir, "keystore.pem"))
	require.NoError(t, err)

	_, err = pemFile.Write(pemBytes)
	require.NoError(t, err)

	for _, tc := range []struct {
		uc             string
		serviceConf    config.ServiceConfig
		enableMetrics  bool
		disableHTTP2   bool
		createRequest  func(t *testing.T, host string) *http.Request
		createClient   func(t *testing.T) *http.Client
		configureMocks func(t *testing.T, exec *mocks4.ExecutorMock, upstreamURL *url.URL)
		processRequest func(t *testing.T, rw http.ResponseWriter, req *http.Request)
		assertResponse func(t *testing.T, err error, upstreamCalled bool, resp *http.Response)
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
			configureMocks: func(t *testing.T, exec *mocks4.ExecutorMock, _ *url.URL) {
				t.Helper()

				exec.EXPECT().Execute(mock.Anything).Return(nil, heimdall.ErrNoRuleFound)
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
			configureMocks: func(t *testing.T, exec *mocks4.ExecutorMock, _ *url.URL) {
				t.Helper()

				exec.EXPECT().Execute(mock.Anything).Return(nil, heimdall.ErrMethodNotAllowed)
			},
			assertResponse: func(t *testing.T, err error, upstreamCalled bool, resp *http.Response) {
				t.Helper()

				require.False(t, upstreamCalled)

				require.NoError(t, err)
				assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)

				data, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Empty(t, data)
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
			configureMocks: func(t *testing.T, exec *mocks4.ExecutorMock, _ *url.URL) {
				t.Helper()

				exec.EXPECT().Execute(mock.Anything).Return(nil, heimdall.ErrConfiguration)
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
			configureMocks: func(t *testing.T, exec *mocks4.ExecutorMock, _ *url.URL) {
				t.Helper()

				exec.EXPECT().Execute(mock.Anything).Return(nil, heimdall.ErrAuthentication)
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
			configureMocks: func(t *testing.T, exec *mocks4.ExecutorMock, _ *url.URL) {
				t.Helper()

				exec.EXPECT().Execute(mock.Anything).Return(nil, heimdall.ErrAuthorization)
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
		{
			uc: "successful rule execution - request method and path are taken from the real request " +
				"(trusted proxy not configured)",
			serviceConf: config.ServiceConfig{
				Timeout: config.Timeout{Read: 1 * time.Second, Write: 1 * time.Second, Idle: 1 * time.Second},
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
				req.Header.Set("X-Forwarded-Method", http.MethodGet)
				req.Header.Set("X-Forwarded-Uri", "/barfoo")

				return req
			},
			configureMocks: func(t *testing.T, exec *mocks4.ExecutorMock, upstreamURL *url.URL) {
				t.Helper()

				backend := mocks4.NewBackendMock(t)
				backend.EXPECT().URL().Return(&url.URL{
					Scheme: upstreamURL.Scheme,
					Host:   upstreamURL.Host,
					Path:   "/foobar",
				})

				exec.EXPECT().Execute(
					mock.MatchedBy(func(ctx heimdall.Context) bool {
						ctx.AddHeaderForUpstream("X-Foo-Bar", "baz")
						ctx.AddCookieForUpstream("X-Bar-Foo", "zab")

						pathMatched := ctx.Request().URL.Path == "/foobar"
						methodMatched := ctx.Request().Method == http.MethodPost

						return pathMatched && methodMatched
					}),
				).Return(backend, nil)
			},
			processRequest: func(t *testing.T, rw http.ResponseWriter, req *http.Request) {
				t.Helper()

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
		{
			uc: "successful rule execution - request method is taken from the header " +
				"(trusted proxy configured)",
			serviceConf: config.ServiceConfig{
				Timeout:        config.Timeout{Read: 1 * time.Second, Write: 1 * time.Second, Idle: 1 * time.Second},
				TrustedProxies: &[]string{"0.0.0.0/0"},
			},
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					context.TODO(),
					http.MethodPost,
					"http://"+host+"/%5Bid%5D/foobar",
					strings.NewReader("hello"))
				require.NoError(t, err)

				req.Header.Set("Content-Type", "text/html")
				req.Header.Set("X-Forwarded-Method", http.MethodGet)

				return req
			},
			configureMocks: func(t *testing.T, exec *mocks4.ExecutorMock, upstreamURL *url.URL) {
				t.Helper()

				backend := mocks4.NewBackendMock(t)
				backend.EXPECT().URL().Return(&url.URL{
					Scheme: upstreamURL.Scheme,
					Host:   upstreamURL.Host,
					Path:   "/[id]/foobar",
				})

				exec.EXPECT().Execute(
					mock.MatchedBy(func(ctx heimdall.Context) bool {
						ctx.AddHeaderForUpstream("X-Foo-Bar", "baz")
						ctx.AddCookieForUpstream("X-Bar-Foo", "zab")

						pathMatched := ctx.Request().URL.Path == "/[id]/foobar"
						methodMatched := ctx.Request().Method == http.MethodGet

						return pathMatched && methodMatched
					}),
				).Return(backend, nil)
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
		{
			uc: "successful rule execution - request path is taken from the header " +
				"(trusted proxy configured)",
			serviceConf: config.ServiceConfig{
				Timeout:        config.Timeout{Read: 1 * time.Second, Write: 1 * time.Second, Idle: 1 * time.Second},
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
				req.Header.Set("X-Forwarded-Uri", "/%5Bbarfoo%5D")

				return req
			},
			configureMocks: func(t *testing.T, exec *mocks4.ExecutorMock, upstreamURL *url.URL) {
				t.Helper()

				backend := mocks4.NewBackendMock(t)
				backend.EXPECT().URL().Return(&url.URL{
					Scheme: upstreamURL.Scheme,
					Host:   upstreamURL.Host,
					Path:   "/[barfoo]",
				})

				exec.EXPECT().Execute(
					mock.MatchedBy(func(ctx heimdall.Context) bool {
						ctx.AddHeaderForUpstream("X-Foo-Bar", "baz")
						ctx.AddCookieForUpstream("X-Bar-Foo", "zab")

						pathMatched := ctx.Request().URL.Path == "/[barfoo]"
						methodMatched := ctx.Request().Method == http.MethodPost

						return pathMatched && methodMatched
					}),
				).Return(backend, nil)
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
		{
			uc: "CORS test actual request",
			serviceConf: config.ServiceConfig{
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
					context.TODO(),
					http.MethodGet,
					fmt.Sprintf("http://%s/foobar", host),
					strings.NewReader("hello"))
				require.NoError(t, err)

				req.Header.Set("Content-Type", "text/html")
				req.Header.Set("Origin", "https://foo.bar")

				return req
			},
			configureMocks: func(t *testing.T, exec *mocks4.ExecutorMock, upstreamURL *url.URL) {
				t.Helper()

				backend := mocks4.NewBackendMock(t)
				backend.EXPECT().URL().Return(&url.URL{
					Scheme: upstreamURL.Scheme,
					Host:   upstreamURL.Host,
					Path:   "/bar",
				})

				exec.EXPECT().Execute(
					mock.MatchedBy(func(ctx heimdall.Context) bool {
						ctx.AddHeaderForUpstream("X-Foo-Bar", "baz")

						pathMatched := ctx.Request().URL.Path == "/foobar"
						methodMatched := ctx.Request().Method == http.MethodGet

						return pathMatched && methodMatched
					}),
				).Return(backend, nil)
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
			configureMocks: func(t *testing.T, _ *mocks4.ExecutorMock, _ *url.URL) { t.Helper() },
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
			configureMocks: func(t *testing.T, _ *mocks4.ExecutorMock, _ *url.URL) { t.Helper() },
			assertResponse: func(t *testing.T, err error, upstreamCalled bool, resp *http.Response) {
				t.Helper()

				require.False(t, upstreamCalled)

				require.NoError(t, err)
				assert.Equal(t, http.StatusNoContent, resp.StatusCode)
			},
		},
		{
			uc: "http2 usage",
			serviceConf: config.ServiceConfig{
				Timeout: config.Timeout{Read: 1000 * time.Second, Write: 1000 * time.Second, Idle: 1000 * time.Second},
				TLS: &config.TLS{
					KeyStore: config.KeyStore{
						Path: pemFile.Name(),
					},
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
					context.TODO(),
					http.MethodGet,
					fmt.Sprintf("https://%s/foobar", host),
					strings.NewReader("hello"))
				require.NoError(t, err)

				return req
			},
			configureMocks: func(t *testing.T, exec *mocks4.ExecutorMock, upstreamURL *url.URL) {
				t.Helper()

				backend := mocks4.NewBackendMock(t)
				backend.EXPECT().URL().Return(&url.URL{
					Scheme: upstreamURL.Scheme,
					Host:   upstreamURL.Host,
					Path:   "/bar",
				})

				exec.EXPECT().Execute(
					mock.MatchedBy(func(ctx heimdall.Context) bool {
						ctx.AddHeaderForUpstream("X-Foo-Bar", "baz")

						pathMatched := ctx.Request().URL.Path == "/foobar"
						methodMatched := ctx.Request().Method == http.MethodGet

						return pathMatched && methodMatched
					}),
				).Return(backend, nil)
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
		{
			uc:           "http2 not supported by upstream server",
			disableHTTP2: true,
			serviceConf: config.ServiceConfig{
				Timeout: config.Timeout{Read: 1 * time.Second, Write: 1 * time.Second, Idle: 1 * time.Second},
				TLS: &config.TLS{
					KeyStore: config.KeyStore{
						Path: pemFile.Name(),
					},
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
					context.TODO(),
					http.MethodGet,
					fmt.Sprintf("https://%s/foobar", host),
					strings.NewReader("hello"))
				require.NoError(t, err)

				return req
			},
			configureMocks: func(t *testing.T, exec *mocks4.ExecutorMock, upstreamURL *url.URL) {
				t.Helper()

				backend := mocks4.NewBackendMock(t)
				backend.EXPECT().URL().Return(&url.URL{
					Scheme: upstreamURL.Scheme,
					Host:   upstreamURL.Host,
					Path:   "/bar",
				})

				exec.EXPECT().Execute(
					mock.MatchedBy(func(ctx heimdall.Context) bool {
						ctx.AddHeaderForUpstream("X-Foo-Bar", "baz")

						pathMatched := ctx.Request().URL.Path == "/foobar"
						methodMatched := ctx.Request().Method == http.MethodGet

						return pathMatched && methodMatched
					}),
				).Return(backend, nil)
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
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			exp := metric.NewManualReader()

			if tc.enableMetrics {
				otel.SetMeterProvider(metric.NewMeterProvider(
					metric.WithResource(resource.Default()),
					metric.WithReader(exp),
				))
			}

			upstreamCalled := false

			processRequest := x.IfThenElse(tc.processRequest != nil, tc.processRequest,
				func(t *testing.T, rw http.ResponseWriter, _ *http.Request) {
					t.Helper()

					rw.WriteHeader(http.StatusOK)
				})

			upstreamSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamCalled = true

				processRequest(t, w, r)
			}))
			defer upstreamSrv.Close()

			upstreamSrv.EnableHTTP2 = !tc.disableHTTP2
			upstreamSrv.StartTLS()

			certPool := x509.NewCertPool()
			certPool.AddCert(upstreamSrv.Certificate())
			tlsClientConfig = &tls.Config{RootCAs: certPool} //nolint:gosec

			upstreamURL, err := url.Parse(upstreamSrv.URL)
			require.NoError(t, err)

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

			listener, err := listener.New("tcp", proxyConf.Address(), proxyConf.TLS, nil)
			require.NoError(t, err)

			conf := &config.Configuration{
				Serve:   config.ServeConfig{Proxy: proxyConf},
				Metrics: config.MetricsConfig{Enabled: tc.enableMetrics},
			}
			cch := mocks.NewCacheMock(t)
			exec := mocks4.NewExecutorMock(t)

			tc.configureMocks(t, exec, upstreamURL)

			client := createClient(t)

			proxy := newService(conf, cch, log.Logger, exec, nil)

			defer proxy.Shutdown(context.Background())

			go func() {
				proxy.Serve(listener)
			}()

			time.Sleep(50 * time.Millisecond)

			// WHEN
			resp, err := client.Do(tc.createRequest(t, proxyConf.Address()))

			// THEN
			if err == nil {
				defer resp.Body.Close()
			}

			tc.assertResponse(t, err, upstreamCalled, resp)

			var rm metricdata.ResourceMetrics

			err = exp.Collect(context.TODO(), &rm)

			if tc.enableMetrics {
				require.NoError(t, err)
				require.NotEmpty(t, rm.ScopeMetrics)
			} else {
				require.Empty(t, rm.ScopeMetrics)
			}
		})
	}
}

func TestWebSocketSupport(t *testing.T) {
	t.Parallel()

	port, err := testsupport.GetFreePort()
	require.NoError(t, err)

	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		require.Equal(t, "/bar", req.URL.Path)

		upgrader := websocket.Upgrader{
			CheckOrigin: func(_ *http.Request) bool {
				return true
			},
		}

		con, err := upgrader.Upgrade(rw, req, nil)
		require.NoError(t, err)

		defer con.Close()

		err = con.WriteMessage(websocket.TextMessage, []byte("ping 1"))
		require.NoError(t, err)

		_, message, err := con.ReadMessage()
		require.NoError(t, err)
		assert.Equal(t, []byte("ping 1"), message)

		err = con.WriteMessage(websocket.TextMessage, []byte("ping 2"))
		require.NoError(t, err)

		_, message, err = con.ReadMessage()
		require.NoError(t, err)
		assert.Equal(t, []byte("ping 2"), message)
	}))
	defer upstreamSrv.Close()

	upstreamURL, err := url.Parse(upstreamSrv.URL)
	require.NoError(t, err)

	exec := mocks4.NewExecutorMock(t)
	backend := mocks4.NewBackendMock(t)
	backend.EXPECT().URL().Return(&url.URL{
		Scheme: upstreamURL.Scheme,
		Host:   upstreamURL.Host,
		Path:   "/bar",
	})

	exec.EXPECT().Execute(
		mock.MatchedBy(func(ctx heimdall.Context) bool {
			pathMatched := ctx.Request().URL.Path == "/foo"
			methodMatched := ctx.Request().Method == http.MethodGet

			return pathMatched && methodMatched
		}),
	).Return(backend, nil)

	conf := &config.Configuration{
		Serve: config.ServeConfig{
			Proxy: config.ServiceConfig{
				Timeout: config.Timeout{
					Read:  1 * time.Second,
					Write: 1 * time.Second,
					Idle:  1 * time.Second,
				},
				Host: "127.0.0.1",
				Port: port,
			},
		},
	}

	proxy := newService(conf, mocks.NewCacheMock(t), log.Logger, exec, nil)

	defer proxy.Shutdown(context.Background())

	listener, err := listener.New("tcp", conf.Serve.Proxy.Address(), conf.Serve.Proxy.TLS, nil)
	require.NoError(t, err)

	go func() {
		proxy.Serve(listener)
	}()

	time.Sleep(50 * time.Millisecond)

	wsURL := url.URL{Scheme: "ws", Host: conf.Serve.Proxy.Address(), Path: "/foo"}
	con, resp, err := websocket.DefaultDialer.Dial(wsURL.String(), nil)
	require.NoError(t, err)

	defer resp.Body.Close()

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
		require.Equal(t, "/bar", req.URL.Path)

		rw.Header().Set("Content-Type", "text/event-stream")
		rw.Header().Set("Cache-Control", "no-cache")
		rw.Header().Set("Connection", "keep-alive")

		rc := http.NewResponseController(rw) // nolint: bodyclose

		for i := range 5 {
			_, err := rw.Write(stringx.ToBytes(strconv.Itoa(i)))
			require.NoError(t, err)

			require.NoError(t, rc.Flush())

			time.Sleep(50 * time.Millisecond)
		}
	}))
	defer upstreamSrv.Close()

	upstreamURL, err := url.Parse(upstreamSrv.URL)
	require.NoError(t, err)

	exec := mocks4.NewExecutorMock(t)

	backend := mocks4.NewBackendMock(t)
	backend.EXPECT().URL().Return(&url.URL{
		Scheme: upstreamURL.Scheme,
		Host:   upstreamURL.Host,
		Path:   "/bar",
	})

	exec.EXPECT().Execute(
		mock.MatchedBy(func(ctx heimdall.Context) bool {
			pathMatched := ctx.Request().URL.Path == "/foo"
			methodMatched := ctx.Request().Method == http.MethodGet

			return pathMatched && methodMatched
		}),
	).Return(backend, nil)

	conf := &config.Configuration{
		Serve: config.ServeConfig{
			Proxy: config.ServiceConfig{
				Timeout: config.Timeout{
					Read:  40 * time.Millisecond,
					Write: 50 * time.Millisecond,
					Idle:  1 * time.Second,
				},
				Host: "127.0.0.1",
				Port: port,
			},
		},
	}

	proxy := newService(conf, mocks.NewCacheMock(t), log.Logger, exec, nil)

	defer proxy.Shutdown(context.Background())

	listener, err := listener.New("tcp", conf.Serve.Proxy.Address(), conf.Serve.Proxy.TLS, nil)
	require.NoError(t, err)

	go func() {
		proxy.Serve(listener)
	}()

	time.Sleep(50 * time.Millisecond)

	req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, fmt.Sprintf("http://%s/foo", conf.Serve.Proxy.Address()), nil)
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

	time.Sleep(60 * time.Millisecond)
}
