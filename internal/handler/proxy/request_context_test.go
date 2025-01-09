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
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/requestcontext"
	"github.com/dadrus/heimdall/internal/rules/rule"
	mocks2 "github.com/dadrus/heimdall/internal/rules/rule/mocks"
)

func TestRequestContextFinalize(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc             string
		upstreamCalled bool
		headers        http.Header
		setup          func(*testing.T, requestcontext.Context, *url.URL) rule.Backend
		assertRequest  func(*testing.T, *http.Request)
	}{
		{
			uc: "error was present, forwarding aborted",
			setup: func(t *testing.T, ctx requestcontext.Context, _ *url.URL) rule.Backend {
				t.Helper()

				err := errors.New("test error")
				ctx.SetPipelineError(err)

				return nil
			},
		},
		{
			uc:             "no headers set",
			upstreamCalled: true,
			setup: func(t *testing.T, _ requestcontext.Context, upstreamURL *url.URL) rule.Backend {
				t.Helper()

				backend := mocks2.NewBackendMock(t)
				backend.EXPECT().URL().Return(upstreamURL)

				return backend
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Contains(t, req.Host, "127.0.0.1")
				assert.Equal(t, http.MethodGet, req.Method)

				require.Len(t, req.Header, 3)
				assert.NotEmpty(t, req.Header.Get("Accept-Encoding"))
				assert.NotEmpty(t, req.Header.Get("Content-Length"))
				assert.Equal(t, "for=192.0.2.1;host=foo.bar;proto=https", req.Header.Get("Forwarded"))
			},
		},
		{
			uc:             "all X-Forwarded-* and Forwarded headers present",
			upstreamCalled: true,
			headers: http.Header{
				"X-Forwarded-Proto":  []string{"https"},
				"X-Forwarded-Host":   []string{"bar.foo"},
				"X-Forwarded-Path":   []string{"/foobar"},
				"X-Forwarded-Uri":    []string{"/barfoo?foo=bar"},
				"X-Forwarded-Method": []string{http.MethodPatch},
				"X-Forwarded-For":    []string{"127.0.0.2, 192.168.12.126"},
				"Forwarded":          []string{"proto=http;for=127.0.0.3, proto=http;for=192.168.12.127"},
			},
			setup: func(t *testing.T, _ requestcontext.Context, upstreamURL *url.URL) rule.Backend {
				t.Helper()

				backend := mocks2.NewBackendMock(t)
				backend.EXPECT().URL().Return(upstreamURL)

				return backend
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Contains(t, req.Host, "127.0.0.1")
				assert.Equal(t, http.MethodPatch, req.Method)

				require.Len(t, req.Header, 5)
				assert.NotEmpty(t, req.Header.Get("Accept-Encoding"))
				assert.NotEmpty(t, req.Header.Get("Content-Length"))
				assert.Equal(t, "127.0.0.2, 192.168.12.126, 192.0.2.1", req.Header.Get("X-Forwarded-For"))
				assert.Equal(t, "bar.foo", req.Header.Get("X-Forwarded-Host"))
				assert.Equal(t, "https", req.Header.Get("X-Forwarded-Proto"))
			},
		},
		{
			uc:             "only X-Forwarded-Method and Forwarded headers are present",
			upstreamCalled: true,
			headers: http.Header{
				"X-Forwarded-Method": []string{http.MethodPost},
				"Forwarded":          []string{"proto=http;for=127.0.0.3, proto=http;for=192.168.12.127"},
			},
			setup: func(t *testing.T, _ requestcontext.Context, upstreamURL *url.URL) rule.Backend {
				t.Helper()

				backend := mocks2.NewBackendMock(t)
				backend.EXPECT().URL().Return(upstreamURL)

				return backend
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Contains(t, req.Host, "127.0.0.1")
				assert.Equal(t, http.MethodPost, req.Method)

				require.Len(t, req.Header, 3)
				assert.NotEmpty(t, req.Header.Get("Accept-Encoding"))
				assert.NotEmpty(t, req.Header.Get("Content-Length"))
				assert.Equal(t, "proto=http;for=127.0.0.3, proto=http;for=192.168.12.127, for=192.0.2.1;host=foo.bar;proto=https", req.Header.Get("Forwarded"))
			},
		},
		{
			uc:             "only custom headers and results from rule execution are present",
			upstreamCalled: true,
			headers: http.Header{
				"X-Foo-Bar": []string{"bar"},
			},
			setup: func(t *testing.T, ctx requestcontext.Context, upstreamURL *url.URL) rule.Backend {
				t.Helper()

				ctx.AddHeaderForUpstream("X-User-ID", "someid")
				ctx.AddHeaderForUpstream("X-Custom", "somevalue")
				ctx.AddHeaderForUpstream("X-Forwarded-Method", http.MethodDelete)
				ctx.AddCookieForUpstream("my_cookie_1", "my_value_1")
				ctx.AddCookieForUpstream("my_cookie_2", "my_value_2")

				backend := mocks2.NewBackendMock(t)
				backend.EXPECT().URL().Return(upstreamURL)

				return backend
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Contains(t, req.Host, "127.0.0.1")
				assert.Equal(t, http.MethodGet, req.Method)

				require.Len(t, req.Header, 8)
				assert.NotEmpty(t, req.Header.Get("Accept-Encoding"))
				assert.NotEmpty(t, req.Header.Get("Content-Length"))
				assert.Contains(t, req.Header.Get("Cookie"), "my_cookie_1=my_value_1")
				assert.Contains(t, req.Header.Get("Cookie"), "my_cookie_2=my_value_2")
				assert.Equal(t, "for=192.0.2.1;host=foo.bar;proto=https", req.Header.Get("Forwarded"))
				assert.Equal(t, "somevalue", req.Header.Get("X-Custom"))
				assert.Equal(t, "bar", req.Header.Get("X-Foo-Bar"))
				assert.Equal(t, http.MethodDelete, req.Header.Get("X-Forwarded-Method"))
				assert.Equal(t, "someid", req.Header.Get("X-User-Id"))
			},
		},
		{
			uc:             "Host header is set for upstream",
			upstreamCalled: true,
			setup: func(t *testing.T, ctx requestcontext.Context, upstreamURL *url.URL) rule.Backend {
				t.Helper()

				ctx.AddHeaderForUpstream("Host", "bar.foo")

				backend := mocks2.NewBackendMock(t)
				backend.EXPECT().URL().Return(upstreamURL)

				return backend
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Contains(t, req.Host, "bar.foo")
				assert.Equal(t, http.MethodGet, req.Method)

				require.Len(t, req.Header, 3)
				assert.NotEmpty(t, req.Header.Get("Accept-Encoding"))
				assert.NotEmpty(t, req.Header.Get("Content-Length"))
				assert.Equal(t, "for=192.0.2.1;host=foo.bar;proto=https", req.Header.Get("Forwarded"))
			},
		},
		{
			uc:             "Only X-Forwarded-Proto header is present",
			upstreamCalled: true,
			headers: http.Header{
				"X-Forwarded-Proto": []string{"http"},
			},
			setup: func(t *testing.T, _ requestcontext.Context, upstreamURL *url.URL) rule.Backend {
				t.Helper()

				backend := mocks2.NewBackendMock(t)
				backend.EXPECT().URL().Return(upstreamURL)

				return backend
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Contains(t, req.Host, "127.0.0.1")
				assert.Equal(t, http.MethodGet, req.Method)

				require.Len(t, req.Header, 5)
				assert.NotEmpty(t, req.Header.Get("Accept-Encoding"))
				assert.NotEmpty(t, req.Header.Get("Content-Length"))
				assert.Equal(t, "http", req.Header.Get("X-Forwarded-Proto"))
				assert.Equal(t, "foo.bar", req.Header.Get("X-Forwarded-Host"))
				assert.Equal(t, "192.0.2.1", req.Header.Get("X-Forwarded-For"))
			},
		},
		{
			uc:             "Only X-Forwarded-Host header is present",
			upstreamCalled: true,
			headers: http.Header{
				"X-Forwarded-Host": []string{"bar.foo"},
			},
			setup: func(t *testing.T, _ requestcontext.Context, upstreamURL *url.URL) rule.Backend {
				t.Helper()

				backend := mocks2.NewBackendMock(t)
				backend.EXPECT().URL().Return(upstreamURL)

				return backend
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Contains(t, req.Host, "127.0.0.1")
				assert.Equal(t, http.MethodGet, req.Method)

				require.Len(t, req.Header, 5)
				assert.NotEmpty(t, req.Header.Get("Accept-Encoding"))
				assert.NotEmpty(t, req.Header.Get("Content-Length"))
				assert.Equal(t, "https", req.Header.Get("X-Forwarded-Proto"))
				assert.Equal(t, "bar.foo", req.Header.Get("X-Forwarded-Host"))
				assert.Equal(t, "192.0.2.1", req.Header.Get("X-Forwarded-For"))
			},
		},
		{
			uc:             "Only X-Forwarded-For header is present",
			upstreamCalled: true,
			headers: http.Header{
				"X-Forwarded-For": []string{"172.2.34.1"},
			},
			setup: func(t *testing.T, _ requestcontext.Context, upstreamURL *url.URL) rule.Backend {
				t.Helper()

				backend := mocks2.NewBackendMock(t)
				backend.EXPECT().URL().Return(upstreamURL)

				return backend
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Contains(t, req.Host, "127.0.0.1")
				assert.Equal(t, http.MethodGet, req.Method)

				require.Len(t, req.Header, 5)
				assert.NotEmpty(t, req.Header.Get("Accept-Encoding"))
				assert.NotEmpty(t, req.Header.Get("Content-Length"))
				assert.Equal(t, "https", req.Header.Get("X-Forwarded-Proto"))
				assert.Equal(t, "foo.bar", req.Header.Get("X-Forwarded-Host"))
				assert.Equal(t, "172.2.34.1, 192.0.2.1", req.Header.Get("X-Forwarded-For"))
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			upstreamCalled := false
			req := httptest.NewRequest(http.MethodGet, "https://foo.bar/test", bytes.NewBufferString("Ping"))
			req.Header = tc.headers
			rw := httptest.NewRecorder()

			srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
				upstreamCalled = true

				tc.assertRequest(t, req)
			}))
			defer srv.Close()

			targetURL, err := url.Parse(srv.URL)
			require.NoError(t, err)

			timeouts := config.Timeout{
				Read:  100 * time.Millisecond,
				Write: 100 * time.Millisecond,
				Idle:  1 * time.Second,
			}
			ctx := newContextFactory(config.ServeConfig{Timeout: timeouts}, nil).Create(rw, req)

			backend := tc.setup(t, ctx, targetURL)

			// WHEN
			err = ctx.Finalize(backend)

			// THEN
			require.Equal(t, tc.upstreamCalled, upstreamCalled)

			if !tc.upstreamCalled {
				require.Error(t, err)
			}
		})
	}
}
