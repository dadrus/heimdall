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
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/requestcontext"
	"github.com/dadrus/heimdall/internal/pipeline/mocks"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestRequestContextFinalize(t *testing.T) {
	t.Parallel()

	timeouts := config.Timeout{
		Read:  100 * time.Millisecond,
		Write: 100 * time.Millisecond,
		Idle:  1 * time.Second,
	}
	cf := newContextFactory(config.ServeConfig{Timeout: timeouts}, nil)

	for uc, tc := range map[string]struct {
		upstreamCalled bool
		useIPv6        bool
		headers        http.Header
		setup          func(*testing.T, requestcontext.Context, *mocks.UpstreamTargetMock, *url.URL)
		assertRequest  func(*testing.T, *http.Request)
	}{
		"error was present, forwarding aborted": {
			setup: func(t *testing.T, ctx requestcontext.Context, _ *mocks.UpstreamTargetMock, _ *url.URL) {
				t.Helper()

				err := assert.AnError
				ctx.SetError(err)
			},
		},
		"no headers set, ipv6 is used": {
			upstreamCalled: true,
			useIPv6:        true,
			setup: func(t *testing.T, ctx requestcontext.Context, target *mocks.UpstreamTargetMock, upstreamURL *url.URL) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = *upstreamURL
				})
				target.EXPECT().ForwardHostHeader().Return(false)

				ctx.PrepareUpstreamView(target)
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Contains(t, req.Host, "127.0.0.1")
				assert.Equal(t, http.MethodGet, req.Method)

				require.Len(t, req.Header, 6)
				assert.NotEmpty(t, req.Header.Get("Accept-Encoding"))
				assert.NotEmpty(t, req.Header.Get("Content-Length"))
				assert.Equal(t, "for=\"[a746:9bbd:955b:e17e:cede:9748:0bf5:f2ea]\";host=\"foo.bar\";proto=https", req.Header.Get("Forwarded"))
				assert.Equal(t, "a746:9bbd:955b:e17e:cede:9748:0bf5:f2ea", req.Header.Get("X-Forwarded-For"))
				assert.Equal(t, "foo.bar", req.Header.Get("X-Forwarded-Host"))
				assert.Equal(t, "https", req.Header.Get("X-Forwarded-Proto"))
			},
		},
		"all X-Forwarded-* and Forwarded headers present, ipv6 is used": {
			upstreamCalled: true,
			useIPv6:        true,
			headers: http.Header{
				"X-Forwarded-Proto":  []string{"https"},
				"X-Forwarded-Host":   []string{"bar.foo"},
				"X-Forwarded-Path":   []string{"/foobar"},
				"X-Forwarded-Uri":    []string{"/barfoo?foo=bar"},
				"X-Forwarded-Method": []string{http.MethodPatch},
				"X-Forwarded-For":    []string{"127.0.0.2, 192.168.12.126"},
				"Forwarded":          []string{"proto=http;for=127.0.0.3, proto=http;for=192.168.12.127"},
			},
			setup: func(t *testing.T, ctx requestcontext.Context, target *mocks.UpstreamTargetMock, upstreamURL *url.URL) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = *upstreamURL
				})
				target.EXPECT().ForwardHostHeader().Return(false)

				ctx.PrepareUpstreamView(target)
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Contains(t, req.Host, "127.0.0.1")
				assert.Equal(t, http.MethodPatch, req.Method)

				require.Len(t, req.Header, 6)
				assert.NotEmpty(t, req.Header.Get("Accept-Encoding"))
				assert.NotEmpty(t, req.Header.Get("Content-Length"))
				assert.Equal(t, "proto=http;for=127.0.0.3, proto=http;for=192.168.12.127, for=\"[a746:9bbd:955b:e17e:cede:9748:0bf5:f2ea]\";host=\"foo.bar\";proto=https", req.Header.Get("Forwarded"))
				assert.Equal(t, "127.0.0.3, 192.168.12.127, a746:9bbd:955b:e17e:cede:9748:0bf5:f2ea", req.Header.Get("X-Forwarded-For"))
				assert.Equal(t, "bar.foo", req.Header.Get("X-Forwarded-Host"))
				assert.Equal(t, "https", req.Header.Get("X-Forwarded-Proto"))
			},
		},
		"Forwarded and X-Forwarded-For appear multiple times": {
			upstreamCalled: true,
			headers: http.Header{
				"X-Forwarded-For": []string{"127.0.0.2", "192.168.12.126"},
				"Forwarded":       []string{"proto=http;for=127.0.0.3", "proto=https;for=192.168.12.127"},
			},
			setup: func(t *testing.T, ctx requestcontext.Context, target *mocks.UpstreamTargetMock, upstreamURL *url.URL) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = *upstreamURL
				})
				target.EXPECT().ForwardHostHeader().Return(false)

				ctx.PrepareUpstreamView(target)
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Contains(t, req.Host, "127.0.0.1")
				assert.Equal(t, http.MethodGet, req.Method)

				require.Len(t, req.Header, 6)
				assert.NotEmpty(t, req.Header.Get("Accept-Encoding"))
				assert.NotEmpty(t, req.Header.Get("Content-Length"))
				assert.Equal(t, "proto=http;for=127.0.0.3, proto=https;for=192.168.12.127, for=192.0.2.1;host=\"foo.bar\";proto=https", req.Header.Get("Forwarded"))
				assert.Equal(t, "127.0.0.3, 192.168.12.127, 192.0.2.1", req.Header.Get("X-Forwarded-For"))
				assert.Equal(t, "foo.bar", req.Header.Get("X-Forwarded-Host"))
				assert.Equal(t, "https", req.Header.Get("X-Forwarded-Proto"))
			},
		},
		"only X-Forwarded-Method, Forwarded, and X-Forwarded-* headers are present": {
			upstreamCalled: true,
			headers: http.Header{
				"X-Forwarded-Method": []string{http.MethodPost},
				"Forwarded":          []string{"proto=http;for=127.0.0.3, proto=http;for=192.168.12.127"},
			},
			setup: func(t *testing.T, ctx requestcontext.Context, target *mocks.UpstreamTargetMock, upstreamURL *url.URL) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = *upstreamURL
				})
				target.EXPECT().ForwardHostHeader().Return(false)

				ctx.PrepareUpstreamView(target)
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Contains(t, req.Host, "127.0.0.1")
				assert.Equal(t, http.MethodPost, req.Method)

				require.Len(t, req.Header, 6)
				assert.NotEmpty(t, req.Header.Get("Accept-Encoding"))
				assert.NotEmpty(t, req.Header.Get("Content-Length"))
				assert.Equal(t, "proto=http;for=127.0.0.3, proto=http;for=192.168.12.127, for=192.0.2.1;host=\"foo.bar\";proto=https", req.Header.Get("Forwarded"))
				assert.Equal(t, "127.0.0.3, 192.168.12.127, 192.0.2.1", req.Header.Get("X-Forwarded-For"))
				assert.Equal(t, "foo.bar", req.Header.Get("X-Forwarded-Host"))
				assert.Equal(t, "https", req.Header.Get("X-Forwarded-Proto"))
			},
		},
		"only custom headers and results from rule execution are present (custom header are not dropped, but proxy owned)": {
			upstreamCalled: true,
			headers: http.Header{
				"X-Foo-Bar": []string{"bar", "foo"},
				"X-Bar":     []string{"bar"},
			},
			setup: func(t *testing.T, ctx requestcontext.Context, target *mocks.UpstreamTargetMock, upstreamURL *url.URL) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = *upstreamURL
				})
				target.EXPECT().ForwardHostHeader().Return(false)

				ctx.PrepareUpstreamView(target)

				ctx.UpstreamRequest().AddHeader("X-User-ID", "someid")
				ctx.UpstreamRequest().AddHeader("X-Custom", "somevalue")
				ctx.UpstreamRequest().AddHeader("X-Forwarded-Method", http.MethodDelete)
				ctx.UpstreamRequest().SetCookie("my_cookie_1", "my_value_1")
				ctx.UpstreamRequest().SetCookie("my_cookie_2", "my_value_2")
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Contains(t, req.Host, "127.0.0.1")
				assert.Equal(t, http.MethodGet, req.Method)

				require.Len(t, req.Header, 11)
				assert.NotEmpty(t, req.Header.Get("Accept-Encoding"))
				assert.NotEmpty(t, req.Header.Get("Content-Length"))
				assert.Contains(t, req.Header.Get("Cookie"), "my_cookie_1=my_value_1")
				assert.Contains(t, req.Header.Get("Cookie"), "my_cookie_2=my_value_2")
				assert.Equal(t, "for=192.0.2.1;host=\"foo.bar\";proto=https", req.Header.Get("Forwarded"))
				assert.Equal(t, "192.0.2.1", req.Header.Get("X-Forwarded-For"))
				assert.Equal(t, "foo.bar", req.Header.Get("X-Forwarded-Host"))
				assert.Equal(t, "https", req.Header.Get("X-Forwarded-Proto"))
				assert.Equal(t, "somevalue", req.Header.Get("X-Custom"))
				assert.ElementsMatch(t, req.Header.Values("X-Foo-Bar"), []string{"bar", "foo"})
				assert.ElementsMatch(t, req.Header.Values("X-Bar"), []string{"bar"})
				assert.Empty(t, req.Header.Get("X-Forwarded-Method"))
				assert.Equal(t, "someid", req.Header.Get("X-User-Id"))
			},
		},
		"only custom headers and results from rule execution are present (custom header and proxy-owned header are dropped)": {
			upstreamCalled: true,
			headers: http.Header{
				"X-Foo-Bar": []string{"bar", "foo"},
				"X-Bar":     []string{"bar"},
			},
			setup: func(t *testing.T, ctx requestcontext.Context, target *mocks.UpstreamTargetMock, upstreamURL *url.URL) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = *upstreamURL
				})
				target.EXPECT().ForwardHostHeader().Return(false)

				ctx.PrepareUpstreamView(target)

				ctx.UpstreamRequest().AddHeader("X-User-ID", "someid")
				ctx.UpstreamRequest().AddHeader("X-Custom", "somevalue")
				ctx.UpstreamRequest().AddHeader("X-Foo-Bar", "from-heimdall-1")
				ctx.UpstreamRequest().AddHeader("X-Foo-Bar", "from-heimdall-2")
				ctx.UpstreamRequest().AddHeader("X-Forwarded-Method", http.MethodDelete)
				ctx.UpstreamRequest().SetCookie("my_cookie_1", "my_value_1")
				ctx.UpstreamRequest().SetCookie("my_cookie_2", "my_value_2")
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Contains(t, req.Host, "127.0.0.1")
				assert.Equal(t, http.MethodGet, req.Method)

				require.Len(t, req.Header, 11)
				assert.NotEmpty(t, req.Header.Get("Accept-Encoding"))
				assert.NotEmpty(t, req.Header.Get("Content-Length"))
				assert.Contains(t, req.Header.Get("Cookie"), "my_cookie_1=my_value_1")
				assert.Contains(t, req.Header.Get("Cookie"), "my_cookie_2=my_value_2")
				assert.Equal(t, "for=192.0.2.1;host=\"foo.bar\";proto=https", req.Header.Get("Forwarded"))
				assert.Equal(t, "192.0.2.1", req.Header.Get("X-Forwarded-For"))
				assert.Equal(t, "foo.bar", req.Header.Get("X-Forwarded-Host"))
				assert.Equal(t, "https", req.Header.Get("X-Forwarded-Proto"))
				assert.Equal(t, "somevalue", req.Header.Get("X-Custom"))
				assert.ElementsMatch(t, req.Header.Values("X-Foo-Bar"), []string{"from-heimdall-1", "from-heimdall-2"})
				assert.ElementsMatch(t, req.Header.Values("X-Bar"), []string{"bar"})
				assert.Empty(t, req.Header.Get("X-Forwarded-Method"))
				assert.Equal(t, "someid", req.Header.Get("X-User-Id"))
			},
		},
		"Host header is manually added for upstream": {
			upstreamCalled: true,
			setup: func(t *testing.T, ctx requestcontext.Context, target *mocks.UpstreamTargetMock, upstreamURL *url.URL) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = *upstreamURL
				})
				target.EXPECT().ForwardHostHeader().Return(false)

				ctx.PrepareUpstreamView(target)
				ctx.UpstreamRequest().AddHeader("Host", "bar.foo")
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Equal(t, "bar.foo", req.Host)
				assert.Equal(t, http.MethodGet, req.Method)

				require.Len(t, req.Header, 6)
				assert.NotEmpty(t, req.Header.Get("Accept-Encoding"))
				assert.NotEmpty(t, req.Header.Get("Content-Length"))
				assert.Equal(t, "for=192.0.2.1;host=\"foo.bar\";proto=https", req.Header.Get("Forwarded"))
				assert.Equal(t, "192.0.2.1", req.Header.Get("X-Forwarded-For"))
				assert.Equal(t, "foo.bar", req.Header.Get("X-Forwarded-Host"))
				assert.Equal(t, "https", req.Header.Get("X-Forwarded-Proto"))
			},
		},
		"only X-Forwarded-Proto header is present, host not set": {
			upstreamCalled: true,
			headers: http.Header{
				"X-Forwarded-Proto": []string{"http"},
			},
			setup: func(t *testing.T, ctx requestcontext.Context, target *mocks.UpstreamTargetMock, upstreamURL *url.URL) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = *upstreamURL
				})
				target.EXPECT().ForwardHostHeader().Return(false)

				ctx.PrepareUpstreamView(target)
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Contains(t, req.Host, "127.0.0.1")
				assert.Equal(t, http.MethodGet, req.Method)

				require.Len(t, req.Header, 6)
				assert.NotEmpty(t, req.Header.Get("Accept-Encoding"))
				assert.NotEmpty(t, req.Header.Get("Content-Length"))
				assert.Equal(t, "for=192.0.2.1;host=\"foo.bar\";proto=https", req.Header.Get("Forwarded"))
				assert.Equal(t, "http", req.Header.Get("X-Forwarded-Proto"))
				assert.Equal(t, "foo.bar", req.Header.Get("X-Forwarded-Host"))
				assert.Equal(t, "192.0.2.1", req.Header.Get("X-Forwarded-For"))
			},
		},
		"only X-Forwarded-Host header is present, host forwarded": {
			upstreamCalled: true,
			headers: http.Header{
				"X-Forwarded-Host": []string{"bar.foo"},
			},
			setup: func(t *testing.T, ctx requestcontext.Context, target *mocks.UpstreamTargetMock, upstreamURL *url.URL) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = *upstreamURL
				})
				target.EXPECT().ForwardHostHeader().Return(true)

				ctx.PrepareUpstreamView(target)
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Equal(t, "foo.bar", req.Host)
				assert.Equal(t, http.MethodGet, req.Method)

				require.Len(t, req.Header, 6)
				assert.NotEmpty(t, req.Header.Get("Accept-Encoding"))
				assert.NotEmpty(t, req.Header.Get("Content-Length"))
				assert.Equal(t, "for=192.0.2.1;host=\"foo.bar\";proto=https", req.Header.Get("Forwarded"))
				assert.Equal(t, "https", req.Header.Get("X-Forwarded-Proto"))
				assert.Equal(t, "bar.foo", req.Header.Get("X-Forwarded-Host"))
				assert.Equal(t, "192.0.2.1", req.Header.Get("X-Forwarded-For"))
			},
		},
		"only X-Forwarded-For header is present, host not forwarded": {
			upstreamCalled: true,
			headers: http.Header{
				"X-Forwarded-For": []string{"172.2.34.1"},
			},
			setup: func(t *testing.T, ctx requestcontext.Context, target *mocks.UpstreamTargetMock, upstreamURL *url.URL) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = *upstreamURL
				})
				target.EXPECT().ForwardHostHeader().Return(false)

				ctx.PrepareUpstreamView(target)
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Contains(t, req.Host, "127.0.0.1")
				assert.Equal(t, http.MethodGet, req.Method)

				require.Len(t, req.Header, 6)
				assert.NotEmpty(t, req.Header.Get("Accept-Encoding"))
				assert.NotEmpty(t, req.Header.Get("Content-Length"))
				assert.Equal(t, "for=192.0.2.1;host=\"foo.bar\";proto=https", req.Header.Get("Forwarded"))
				assert.Equal(t, "https", req.Header.Get("X-Forwarded-Proto"))
				assert.Equal(t, "foo.bar", req.Header.Get("X-Forwarded-Host"))
				assert.Equal(t, "172.2.34.1, 192.0.2.1", req.Header.Get("X-Forwarded-For"))
			},
		},
		"header is set for upstream": {
			upstreamCalled: true,
			headers: http.Header{
				"X-Foo-Bar": []string{"bar"},
			},
			setup: func(t *testing.T, ctx requestcontext.Context, target *mocks.UpstreamTargetMock, upstreamURL *url.URL) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = *upstreamURL
				})
				target.EXPECT().ForwardHostHeader().Return(false)

				ctx.PrepareUpstreamView(target)

				ctx.UpstreamRequest().SetHeader("X-Foo-Bar", "baz")
				ctx.UpstreamRequest().SetHeader("X-Set", "foo")
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Contains(t, req.Host, "127.0.0.1")
				assert.Equal(t, http.MethodGet, req.Method)
				assert.Equal(t, "baz", req.Header.Get("X-Foo-Bar"))
				assert.Equal(t, "foo", req.Header.Get("X-Set"))
				assert.Equal(t, "for=192.0.2.1;host=\"foo.bar\";proto=https", req.Header.Get("Forwarded"))
				assert.Equal(t, "192.0.2.1", req.Header.Get("X-Forwarded-For"))
				assert.Equal(t, "foo.bar", req.Header.Get("X-Forwarded-Host"))
				assert.Equal(t, "https", req.Header.Get("X-Forwarded-Proto"))
			},
		},
		"proxying fails": {
			setup: func(t *testing.T, ctx requestcontext.Context, target *mocks.UpstreamTargetMock, upstreamURL *url.URL) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = *upstreamURL
				})
				target.EXPECT().ForwardHostHeader().Return(false)

				ctx.PrepareUpstreamView(target)

				ctx.(*requestContext).rt = roundTripperFunc(func(_ *http.Request) (*http.Response, error) {
					return nil, assert.AnError
				})
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			upstreamCalled := false
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://foo.bar/test", bytes.NewBufferString("Ping"))
			req.Header = tc.headers

			if tc.useIPv6 {
				req.RemoteAddr = "[a746:9bbd:955b:e17e:cede:9748:0bf5:f2ea]:1234"
			}

			rw := httptest.NewRecorder()

			srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
				upstreamCalled = true

				tc.assertRequest(t, req)
			}))
			defer srv.Close()

			targetURL, err := url.Parse(srv.URL)
			require.NoError(t, err)

			ctx := cf.Create(rw, req)

			defer cf.Destroy(ctx)

			target := mocks.NewUpstreamTargetMock(t)
			tc.setup(t, ctx, target, targetURL)

			// WHEN
			err = ctx.Finalize()

			// THEN
			require.Equal(t, tc.upstreamCalled, upstreamCalled)

			if !tc.upstreamCalled {
				require.Error(t, err)
			}
		})
	}
}

func TestRequestContextReset(t *testing.T) {
	t.Parallel()

	// GIVEN
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://foo.bar/test", nil)

	ctx := &requestContext{NetHTTPRequestContext: requestcontext.New()}
	ctx.Init(httptest.NewRecorder(), req, http.DefaultTransport)

	target := mocks.NewUpstreamTargetMock(t)
	target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
		targetURL.Host = "upstream.local:8080"
	})
	target.EXPECT().ForwardHostHeader().Return(false)

	ctx.PrepareUpstreamView(target)
	ctx.SetHeader("X-Foo-Bar", "baz")
	ctx.SetCookie("foo", "bar")

	// WHEN
	ctx.Reset()

	// THEN
	require.Nil(t, ctx.rw)
	require.Nil(t, ctx.req)
	require.Nil(t, ctx.rt)
	require.Empty(t, ctx.routingURL)
	require.False(t, ctx.upstreamViewPrepared)
	require.False(t, ctx.hasUpstreamTarget)
	require.Empty(t, ctx.UpstreamHeaders())
	require.Nil(t, ctx.UpstreamRequest())
}

func TestRequestContextUpstreamRequest(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		prepare  bool
		expected bool
	}{
		"upstream view is not prepared": {
			prepare:  false,
			expected: false,
		},
		"upstream view is prepared without target": {
			prepare:  true,
			expected: true,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://foo.bar/test", nil)
			ctx := &requestContext{NetHTTPRequestContext: requestcontext.New()}
			ctx.Init(httptest.NewRecorder(), req, nil)

			if tc.prepare {
				ctx.PrepareUpstreamView(nil)
			}

			// WHEN
			upstreamRequest := ctx.UpstreamRequest()

			// THEN
			if tc.expected {
				assert.Same(t, ctx, upstreamRequest)
			} else {
				assert.Nil(t, upstreamRequest)
			}
		})
	}
}

func TestRequestContextURL(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		target            *url.URL
		forwardHostHeader bool
		expectedURL       string
		expectedHost      string
	}{
		"without upstream target": {
			expectedURL:  "https:///test?bar=baz",
			expectedHost: "foo.bar",
		},
		"host is forwarded": {
			target: &url.URL{
				Scheme:   "http",
				Host:     "upstream.local:8080",
				Path:     "/rewritten",
				RawQuery: "foo=bar",
			},
			forwardHostHeader: true,
			expectedURL:       "http://upstream.local:8080/rewritten?foo=bar",
			expectedHost:      "foo.bar",
		},
		"host is not forwarded": {
			target: &url.URL{
				Scheme:   "http",
				Host:     "upstream.local:8080",
				Path:     "/rewritten",
				RawQuery: "foo=bar",
			},
			forwardHostHeader: false,
			expectedURL:       "http://upstream.local:8080/rewritten?foo=bar",
			expectedHost:      "upstream.local:8080",
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			req := httptest.NewRequestWithContext(
				t.Context(),
				http.MethodGet,
				"https://foo.bar/test?bar=baz",
				nil,
			)

			ctx := &requestContext{NetHTTPRequestContext: requestcontext.New()}
			ctx.Init(httptest.NewRecorder(), req, nil)

			if tc.target == nil {
				ctx.PrepareUpstreamView(nil)
			} else {
				target := mocks.NewUpstreamTargetMock(t)
				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = *tc.target
				})
				target.EXPECT().ForwardHostHeader().Return(tc.forwardHostHeader)

				ctx.PrepareUpstreamView(target)
			}

			// WHEN
			actual := ctx.URL()

			// THEN
			assert.Equal(t, tc.expectedURL, actual.String())
			assert.Equal(t, tc.expectedHost, ctx.Headers().Get("Host"))

			actual.Host = "changed.local"

			current := ctx.URL()
			assert.Equal(t, tc.expectedURL, current.String())
			assert.Equal(t, tc.expectedHost, ctx.Headers().Get("Host"))
		})
	}
}

func TestRequestContextHostMutationDoesNotChangeURL(t *testing.T) {
	t.Parallel()

	// GIVEN
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://foo.bar/test", nil)

	ctx := &requestContext{NetHTTPRequestContext: requestcontext.New()}
	ctx.Init(httptest.NewRecorder(), req, nil)

	target := mocks.NewUpstreamTargetMock(t)
	target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
		targetURL.Scheme = "http"
		targetURL.Host = "upstream.local:8080"
	})
	target.EXPECT().ForwardHostHeader().Return(false)

	ctx.PrepareUpstreamView(target)

	// WHEN
	ctx.AddHeader("Host", "bar.foo")

	// THEN
	actual := ctx.URL()

	assert.Equal(t, "upstream.local:8080", actual.Host)
	assert.Equal(t, "bar.foo", ctx.Headers().Get("Host"))
	assert.Equal(t, "upstream.local:8080", ctx.routingURL.Host)
	assert.Equal(t, "foo.bar", ctx.Request().URL.Host)
	assert.Equal(t, "foo.bar", ctx.Request().Header("Host"))
}

func TestRequestContextPreparedHeaders(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		configureRequest func(t *testing.T, req *http.Request)
		updateContext    func(t *testing.T, ctx *requestContext)
		assert           func(t *testing.T, headers http.Header)
	}{
		"prepared headers reflect proxy sanitization and forwarding": {
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Foo-Bar", "baz")
				req.Header.Set("Host", "spoofed")
				req.Header.Set("Connection", "X-Hop")
				req.Header.Set("X-Hop", "foo")
				req.Header.Set("Keep-Alive", "timeout=5")
				req.Header.Set("X-Forwarded-Method", http.MethodPatch)
				req.Header.Set("X-Forwarded-Uri", "/foo")
				req.Header.Set("X-Forwarded-Path", "/foo")
			},
			assert: func(t *testing.T, headers http.Header) {
				t.Helper()

				assert.Equal(t, "baz", headers.Get("X-Foo-Bar"))
				assert.Equal(t, "foo.bar", headers.Get("Host"))
				assert.Empty(t, headers.Get("Connection"))
				assert.Empty(t, headers.Get("X-Hop"))
				assert.Empty(t, headers.Get("Keep-Alive"))
				assert.Empty(t, headers.Get("X-Forwarded-Method"))
				assert.Empty(t, headers.Get("X-Forwarded-Uri"))
				assert.Empty(t, headers.Get("X-Forwarded-Path"))
				assert.Equal(
					t,
					"for=192.0.2.1;host=\"foo.bar\";proto=https",
					headers.Get("Forwarded"),
				)
				assert.Equal(t, "192.0.2.1", headers.Get("X-Forwarded-For"))
				assert.Equal(t, "foo.bar", headers.Get("X-Forwarded-Host"))
				assert.Equal(t, "https", headers.Get("X-Forwarded-Proto"))
			},
		},
		"sanitized protected header cannot be added again by a finalizer": {
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-Method", http.MethodPatch)
			},
			updateContext: func(t *testing.T, ctx *requestContext) {
				t.Helper()

				ctx.AddHeader("X-Forwarded-Method", http.MethodDelete)
			},
			assert: func(t *testing.T, headers http.Header) {
				t.Helper()

				assert.Empty(t, headers.Get("X-Forwarded-Method"))
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://foo.bar/test", nil)

			if tc.configureRequest != nil {
				tc.configureRequest(t, req)
			}

			ctx := &requestContext{NetHTTPRequestContext: requestcontext.New()}
			ctx.Init(httptest.NewRecorder(), req, nil)
			ctx.PrepareUpstreamView(nil)

			if tc.updateContext != nil {
				tc.updateContext(t, ctx)
			}

			// WHEN
			headers := ctx.Headers()

			// THEN
			tc.assert(t, headers)
		})
	}
}

func TestRequestContextWithParent(t *testing.T) {
	t.Parallel()

	// GIVEN
	ctx := &requestContext{
		NetHTTPRequestContext: requestcontext.New(),
	}
	ctx.Init(
		httptest.NewRecorder(),
		httptest.NewRequestWithContext(
			context.TODO(),
			http.MethodGet,
			"https://foo.bar/test",
			nil,
		),
		nil,
	)

	orig := ctx.Context()

	// WHEN
	actual := ctx.WithParent(t.Context())

	// THEN
	assert.Same(t, ctx, actual)
	assert.NotEqual(t, orig, ctx.Context())
	assert.Equal(t, t.Context(), ctx.Context())
}
