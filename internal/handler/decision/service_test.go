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
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/listener"
	"github.com/dadrus/heimdall/internal/handler/testsupport/hmstest"
	"github.com/dadrus/heimdall/internal/pipeline"
	mocks2 "github.com/dadrus/heimdall/internal/pipeline/mocks"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestHandleDecisionEndpointRequest(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		serviceConf    config.ServeConfig
		createRequest  func(t *testing.T, host string) *http.Request
		configureMocks func(t *testing.T, exec *mocks2.ExecutorMock)
		assertResponse func(t *testing.T, err error, response *http.Response)
	}{
		"no rules configured": {
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					t.Context(),
					http.MethodGet,
					fmt.Sprintf("http://%s/", host),
					nil,
				)
				require.NoError(t, err)

				return req
			},
			configureMocks: func(t *testing.T, exec *mocks2.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(mock.Anything).Return(nil, pipeline.ErrNoRuleFound)
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
		"rule doesn't match method": {
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					t.Context(),
					http.MethodPost,
					fmt.Sprintf("http://%s/", host),
					nil,
				)
				require.NoError(t, err)

				return req
			},
			configureMocks: func(t *testing.T, exec *mocks2.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(mock.Anything).Return(nil, pipeline.ErrNoRuleFound)
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
		"rule execution fails with authentication error": {
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					t.Context(),
					http.MethodPost,
					fmt.Sprintf("http://%s/", host),
					nil,
				)
				require.NoError(t, err)

				return req
			},
			configureMocks: func(t *testing.T, exec *mocks2.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(mock.Anything).Return(nil, pipeline.ErrAuthentication)
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
		"rule execution fails with authorization error": {
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					t.Context(),
					http.MethodPost,
					fmt.Sprintf("http://%s/", host),
					nil,
				)
				require.NoError(t, err)

				return req
			},
			configureMocks: func(t *testing.T, exec *mocks2.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(mock.Anything).Return(nil, pipeline.ErrAuthorization)
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
		"successful rule execution - request method, path and hostname " +
			"are taken from the real request (trusted proxy not configured)": {
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					t.Context(),
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
			configureMocks: func(t *testing.T, exec *mocks2.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(
					mock.MatchedBy(func(ctx pipeline.Context) bool {
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
		"successful rule execution - request method, path and hostname " +
			"are not taken from the headers (trusted proxy not configured)": {
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					t.Context(),
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
			configureMocks: func(t *testing.T, exec *mocks2.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(
					mock.MatchedBy(func(ctx pipeline.Context) bool {
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
		"successful rule execution - request method, path and hostname " +
			"all are not taken from the headers (trusted proxy configured and does not match host)": {
			serviceConf: config.ServeConfig{TrustedProxies: []string{"111.111.111.111"}},
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					t.Context(),
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
			configureMocks: func(t *testing.T, exec *mocks2.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(
					mock.MatchedBy(func(ctx pipeline.Context) bool {
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
		"successful rule execution - only request method is sent via header" +
			"(trusted proxy configured and matches host)": {
			serviceConf: config.ServeConfig{TrustedProxies: []string{"0.0.0.0/0"}},
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					t.Context(),
					http.MethodPost,
					fmt.Sprintf("http://%s/foobar", host),
					nil,
				)
				require.NoError(t, err)

				req.Header.Set("X-Forwarded-Method", http.MethodGet)

				return req
			},
			configureMocks: func(t *testing.T, exec *mocks2.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(
					mock.MatchedBy(func(ctx pipeline.Context) bool {
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
		"successful rule execution - only host is sent via header" +
			"(trusted proxy configured and matches host)": {
			serviceConf: config.ServeConfig{TrustedProxies: []string{"0.0.0.0/0"}},
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					t.Context(),
					http.MethodPost,
					fmt.Sprintf("http://%s/foobar", host),
					nil,
				)
				require.NoError(t, err)

				req.Header.Set("X-Forwarded-Host", "test.com")

				return req
			},
			configureMocks: func(t *testing.T, exec *mocks2.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(
					mock.MatchedBy(func(ctx pipeline.Context) bool {
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
		"successful rule execution - only path is sent via header" +
			"(trusted proxy configured and matches host)": {
			serviceConf: config.ServeConfig{TrustedProxies: []string{"0.0.0.0/0"}},
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					t.Context(),
					http.MethodPost,
					fmt.Sprintf("http://%s/foobar", host),
					nil,
				)
				require.NoError(t, err)

				req.Header.Set("X-Forwarded-Uri", "/bar")

				return req
			},
			configureMocks: func(t *testing.T, exec *mocks2.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(
					mock.MatchedBy(func(ctx pipeline.Context) bool {
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
		"successful rule execution - only scheme is sent via header" +
			"(trusted proxy configured and matches host)": {
			serviceConf: config.ServeConfig{TrustedProxies: []string{"0.0.0.0/0"}},
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					t.Context(),
					http.MethodPost,
					fmt.Sprintf("http://%s/foobar", host),
					nil,
				)
				require.NoError(t, err)

				req.Header.Set("X-Forwarded-Proto", "https")

				return req
			},
			configureMocks: func(t *testing.T, exec *mocks2.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(
					mock.MatchedBy(func(ctx pipeline.Context) bool {
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
		"successful rule execution - scheme, host, path and method sent via header" +
			"(trusted proxy configured and matches host)": {
			serviceConf: config.ServeConfig{TrustedProxies: []string{"0.0.0.0/0"}},
			createRequest: func(t *testing.T, host string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					t.Context(),
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
			configureMocks: func(t *testing.T, exec *mocks2.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(
					mock.MatchedBy(func(ctx pipeline.Context) bool {
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
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			port, err := testsupport.GetFreePort()
			require.NoError(t, err)

			srvConf := tc.serviceConf
			srvConf.Host = "127.0.0.1"
			srvConf.Port = port

			factory, err := listener.NewFactory(
				srvConf.Address(),
				srvConf.TLS,
				nil,
			)
			require.NoError(t, err)

			listener, err := factory.Create(t.Context())
			require.NoError(t, err)

			conf := &config.Configuration{Serve: srvConf}
			cch := mocks.NewCacheMock(t)
			exec := mocks2.NewExecutorMock(t)

			tc.configureMocks(t, exec)

			client := &http.Client{Transport: &http.Transport{}}

			decision := newService(conf, cch, log.Logger, exec)
			defer decision.Shutdown(t.Context())

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

func TestDecisionServiceHTTPMessageSignaturesAuthenticator(t *testing.T) {
	t.Parallel()

	port, err := testsupport.GetFreePort()
	require.NoError(t, err)

	privateKey := hmstest.NewEd25519PrivateKey(t)
	authenticator := hmstest.NewHTTPMessageSignaturesAuthenticatorStep(
		t,
		privateKey,
		hmstest.RequestWithDigestComponents(),
	)

	exec := mocks2.NewExecutorMock(t)
	exec.EXPECT().Execute(mock.Anything).RunAndReturn(func(ctx pipeline.Context) (pipeline.Backend, error) {
		sub := make(pipeline.Subject)

		return nil, authenticator.Execute(ctx, sub)
	})

	conf := &config.Configuration{
		Serve: config.ServeConfig{
			Timeout: config.Timeout{
				Read:  time.Second,
				Write: time.Second,
				Idle:  time.Second,
			},
			Host: "127.0.0.1",
			Port: port,
		},
	}

	decision := newService(conf, mocks.NewCacheMock(t), log.Logger, exec)
	defer decision.Shutdown(t.Context())

	factory, err := listener.NewFactory(conf.Serve.Address(), conf.Serve.TLS, nil)
	require.NoError(t, err)

	lstnr, err := factory.Create(t.Context())
	require.NoError(t, err)

	go func() {
		_ = decision.Serve(lstnr)
	}()

	time.Sleep(50 * time.Millisecond)

	body := []byte(`{"message":"hello"}`)
	req, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		fmt.Sprintf("http://%s/foo", conf.Serve.Address()),
		bytes.NewReader(body),
	)
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	hmstest.SignRequest(t, req, privateKey, hmstest.RequestWithDigestComponents())

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestDecisionServiceHTTPMessageSignaturesFinalizer(t *testing.T) {
	t.Parallel()

	port, err := testsupport.GetFreePort()
	require.NoError(t, err)

	privateKey := hmstest.NewEd25519PrivateKey(t)
	finalizer := hmstest.NewHTTPMessageSignaturesFinalizerStep(
		t,
		privateKey,
		hmstest.RequestWithDigestComponents(),
	)

	exec := mocks2.NewExecutorMock(t)
	exec.EXPECT().Execute(mock.Anything).RunAndReturn(func(ctx pipeline.Context) (pipeline.Backend, error) {
		return nil, finalizer.Execute(ctx, make(pipeline.Subject))
	})

	conf := &config.Configuration{
		Serve: config.ServeConfig{
			Timeout: config.Timeout{
				Read:  time.Second,
				Write: time.Second,
				Idle:  time.Second,
			},
			Host: "127.0.0.1",
			Port: port,
		},
	}

	decision := newService(conf, mocks.NewCacheMock(t), log.Logger, exec)
	defer decision.Shutdown(t.Context())

	factory, err := listener.NewFactory(conf.Serve.Address(), conf.Serve.TLS, nil)
	require.NoError(t, err)

	lstnr, err := factory.Create(t.Context())
	require.NoError(t, err)

	go func() {
		_ = decision.Serve(lstnr)
	}()

	time.Sleep(50 * time.Millisecond)

	body := []byte(`{"message":"hello"}`)
	req, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		fmt.Sprintf("http://%s/foo", conf.Serve.Address()),
		bytes.NewReader(body),
	)
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", strconv.Itoa(len(body)))

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.NotEmpty(t, resp.Header.Get("Signature"))
	assert.NotEmpty(t, resp.Header.Get("Signature-Input"))
	assert.NotEmpty(t, resp.Header.Get("Content-Digest"))

	signedReq, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		fmt.Sprintf("http://%s/foo", conf.Serve.Address()),
		bytes.NewReader(body),
	)
	require.NoError(t, err)

	signedReq.Header.Set("Content-Type", "application/json")
	signedReq.Header.Set("Content-Length", strconv.Itoa(len(body)))
	signedReq.Header.Set("Signature", resp.Header.Get("Signature"))
	signedReq.Header.Set("Signature-Input", resp.Header.Get("Signature-Input"))
	signedReq.Header.Set("Content-Digest", resp.Header.Get("Content-Digest"))

	hmstest.VerifyRequest(t, signedReq, privateKey, hmstest.RequestWithDigestComponents())
}
