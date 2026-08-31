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

				ctx.PrepareUpstreamRequest(target)
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

				ctx.PrepareUpstreamRequest(target)
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

				ctx.PrepareUpstreamRequest(target)
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

				ctx.PrepareUpstreamRequest(target)
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
		"only custom headers and results from rule execution are present (custom header are not dropped)": {
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

				ctx.PrepareUpstreamRequest(target)

				ctx.AddHeaderForUpstream("X-User-ID", "someid")
				ctx.AddHeaderForUpstream("X-Custom", "somevalue")
				ctx.AddHeaderForUpstream("X-Forwarded-Method", http.MethodDelete)
				ctx.AddCookieForUpstream("my_cookie_1", "my_value_1")
				ctx.AddCookieForUpstream("my_cookie_2", "my_value_2")
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Contains(t, req.Host, "127.0.0.1")
				assert.Equal(t, http.MethodGet, req.Method)

				require.Len(t, req.Header, 12)
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
				assert.Equal(t, http.MethodDelete, req.Header.Get("X-Forwarded-Method"))
				assert.Equal(t, "someid", req.Header.Get("X-User-Id"))
			},
		},
		"only custom headers and results from rule execution are present (custom header are dropped)": {
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

				ctx.PrepareUpstreamRequest(target)

				ctx.AddHeaderForUpstream("X-User-ID", "someid")
				ctx.AddHeaderForUpstream("X-Custom", "somevalue")
				ctx.AddHeaderForUpstream("X-Foo-Bar", "from-heimdall-1")
				ctx.AddHeaderForUpstream("X-Foo-Bar", "from-heimdall-2")
				ctx.AddHeaderForUpstream("X-Forwarded-Method", http.MethodDelete)
				ctx.AddCookieForUpstream("my_cookie_1", "my_value_1")
				ctx.AddCookieForUpstream("my_cookie_2", "my_value_2")
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Contains(t, req.Host, "127.0.0.1")
				assert.Equal(t, http.MethodGet, req.Method)

				require.Len(t, req.Header, 12)
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
				assert.Equal(t, http.MethodDelete, req.Header.Get("X-Forwarded-Method"))
				assert.Equal(t, "someid", req.Header.Get("X-User-Id"))
			},
		},
		"Host header is manually set for upstream": {
			upstreamCalled: true,
			setup: func(t *testing.T, ctx requestcontext.Context, target *mocks.UpstreamTargetMock, upstreamURL *url.URL) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = *upstreamURL
				})
				target.EXPECT().ForwardHostHeader().Return(false)

				ctx.PrepareUpstreamRequest(target)

				ctx.AddHeaderForUpstream("Host", "bar.foo")
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Contains(t, req.Host, "bar.foo")
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

				ctx.PrepareUpstreamRequest(target)
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

				ctx.PrepareUpstreamRequest(target)
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Contains(t, req.Host, "foo.bar")
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

				ctx.PrepareUpstreamRequest(target)
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
		"headers are replaced": {
			upstreamCalled: true,
			headers: http.Header{
				"Te":        []string{"trailers"},
				"X-Foo-Bar": []string{"bar"},
			},
			setup: func(t *testing.T, ctx requestcontext.Context, target *mocks.UpstreamTargetMock, upstreamURL *url.URL) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = *upstreamURL
				})
				target.EXPECT().ForwardHostHeader().Return(false)

				ctx.PrepareUpstreamRequest(target)

				upstreamRequest := ctx.UpstreamRequest()
				headers := upstreamRequest.HeaderSnapshot()
				headers.Del("X-Foo-Bar")
				headers.Set("X-Replaced", "foo")

				upstreamRequest.ReplaceHeaders(headers)
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Contains(t, req.Host, "127.0.0.1")
				assert.Equal(t, http.MethodGet, req.Method)
				assert.Empty(t, req.Header.Get("X-Foo-Bar"))
				assert.Equal(t, "foo", req.Header.Get("X-Replaced"))
				assert.Equal(t, "trailers", req.Header.Get("Te"))
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

				ctx.PrepareUpstreamRequest(target)

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

	ctx := &requestContext{RequestContext: requestcontext.New()}
	ctx.Init(httptest.NewRecorder(), req, http.DefaultTransport)

	target := mocks.NewUpstreamTargetMock(t)
	target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
		targetURL.Host = "upstream.local:8080"
	})
	target.EXPECT().ForwardHostHeader().Return(false)

	ctx.PrepareUpstreamRequest(target)
	ctx.ReplaceHeaders(http.Header{
		"X-Foo-Bar": []string{"baz"},
	})

	// WHEN
	ctx.Reset()

	// THEN
	require.Nil(t, ctx.rw)
	require.Nil(t, ctx.req)
	require.Nil(t, ctx.rt)
	require.Empty(t, ctx.routingURL)
	require.Empty(t, ctx.authority)
	require.Nil(t, ctx.replacedHeaders)
	require.Empty(t, ctx.forwardedHeader)
	require.Empty(t, ctx.xForwardedForHeader)
	require.Empty(t, ctx.xForwardedHostHeader)
	require.Empty(t, ctx.xForwardedProtoHeader)
	require.False(t, ctx.upstreamPrepared)
	require.False(t, ctx.hasUpstreamTarget)
	require.Nil(t, ctx.UpstreamRequest())
}

func TestRequestContextUpstreamRequest(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		prepare  bool
		expected bool
	}{
		"upstream request is not prepared": {
			prepare:  false,
			expected: false,
		},
		"upstream request is prepared without target": {
			prepare:  true,
			expected: true,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://foo.bar/test", nil)
			ctx := &requestContext{RequestContext: requestcontext.New()}
			ctx.Init(httptest.NewRecorder(), req, nil)

			if tc.prepare {
				ctx.PrepareUpstreamRequest(nil)
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

func TestRequestContextMethod(t *testing.T) {
	t.Parallel()

	// GIVEN
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://foo.bar/test", nil)
	req.Header.Set("X-Forwarded-Method", http.MethodPatch)

	ctx := &requestContext{RequestContext: requestcontext.New()}
	ctx.Init(httptest.NewRecorder(), req, nil)
	ctx.PrepareUpstreamRequest(nil)

	// WHEN
	method := ctx.Method()

	// THEN
	assert.Equal(t, http.MethodPatch, method)
}

func TestRequestContextAuthority(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		targetHost        string
		forwardHostHeader bool
		expected          string
	}{
		"without upstream target": {
			expected: "foo.bar",
		},
		"host is forwarded": {
			targetHost:        "upstream.local:8080",
			forwardHostHeader: true,
			expected:          "foo.bar",
		},
		"host is not forwarded": {
			targetHost:        "upstream.local:8080",
			forwardHostHeader: false,
			expected:          "upstream.local:8080",
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://foo.bar/test", nil)
			req.Header.Set("X-Forwarded-Host", "bar.foo")

			ctx := &requestContext{RequestContext: requestcontext.New()}
			ctx.Init(httptest.NewRecorder(), req, nil)

			if len(tc.targetHost) == 0 {
				ctx.PrepareUpstreamRequest(nil)
			} else {
				target := mocks.NewUpstreamTargetMock(t)
				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					targetURL.Host = tc.targetHost
				})
				target.EXPECT().ForwardHostHeader().Return(tc.forwardHostHeader)

				ctx.PrepareUpstreamRequest(target)
			}

			// WHEN
			authority := ctx.Authority()

			// THEN
			assert.Equal(t, tc.expected, authority)
		})
	}
}

func TestRequestContextURL(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		target            *url.URL
		forwardHostHeader bool
		expected          string
	}{
		"without upstream target": {
			expected: "https://foo.bar/test?bar=baz",
		},
		"host is forwarded": {
			target: &url.URL{
				Scheme:   "http",
				Host:     "upstream.local:8080",
				Path:     "/rewritten",
				RawQuery: "foo=bar",
			},
			forwardHostHeader: true,
			expected:          "http://foo.bar/rewritten?foo=bar",
		},
		"host is not forwarded": {
			target: &url.URL{
				Scheme:   "http",
				Host:     "upstream.local:8080",
				Path:     "/rewritten",
				RawQuery: "foo=bar",
			},
			forwardHostHeader: false,
			expected:          "http://upstream.local:8080/rewritten?foo=bar",
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

			ctx := &requestContext{RequestContext: requestcontext.New()}
			ctx.Init(httptest.NewRecorder(), req, nil)

			if tc.target == nil {
				ctx.PrepareUpstreamRequest(nil)
			} else {
				target := mocks.NewUpstreamTargetMock(t)
				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = *tc.target
				})
				target.EXPECT().ForwardHostHeader().Return(tc.forwardHostHeader)

				ctx.PrepareUpstreamRequest(target)
			}

			// WHEN
			actual := ctx.URL()
			targetURL := actual

			// THEN
			assert.Equal(t, tc.expected, targetURL.String())

			targetURL.Host = "changed.local"

			assert.Equal(t, tc.expected, actual.String())
		})
	}
}

func TestRequestContextAddHeader(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		name   string
		value  string
		assert func(t *testing.T, ctx *requestContext)
	}{
		"regular header": {
			name:  "X-Foo-Bar",
			value: "baz",
			assert: func(t *testing.T, ctx *requestContext) {
				t.Helper()

				assert.Equal(t, []string{"baz"}, ctx.UpstreamHeaders().Values("X-Foo-Bar"))
				assert.Equal(t, "foo.bar", ctx.Authority())
			},
		},
		"Host header": {
			name:  "host",
			value: "bar.foo",
			assert: func(t *testing.T, ctx *requestContext) {
				t.Helper()

				assert.Empty(t, ctx.UpstreamHeaders().Values("Host"))
				assert.Equal(t, "bar.foo", ctx.Authority())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://foo.bar/test", nil)

			ctx := &requestContext{RequestContext: requestcontext.New()}
			ctx.Init(httptest.NewRecorder(), req, nil)
			ctx.PrepareUpstreamRequest(nil)

			// WHEN
			ctx.AddHeader(tc.name, tc.value)

			// THEN
			tc.assert(t, ctx)
		})
	}
}

func TestRequestContextSetCookie(t *testing.T) {
	t.Parallel()

	// GIVEN
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://foo.bar/test", nil)

	ctx := &requestContext{RequestContext: requestcontext.New()}
	ctx.Init(httptest.NewRecorder(), req, nil)
	ctx.PrepareUpstreamRequest(nil)

	ctx.AddCookieForUpstream("foo", "bar")

	// WHEN
	ctx.SetCookie("foo", "baz")

	// THEN
	require.Len(t, ctx.UpstreamCookies(), 1)
	assert.Equal(t, "baz", ctx.UpstreamCookies()["foo"])
}

func TestRequestContextHeaderSnapshot(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		configureRequest func(t *testing.T, req *http.Request)
		updateContext    func(t *testing.T, ctx *requestContext)
		assert           func(t *testing.T, ctx *requestContext, headers http.Header)
	}{
		"prepared headers are returned": {
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
			assert: func(t *testing.T, _ *requestContext, headers http.Header) {
				t.Helper()

				assert.Equal(t, "baz", headers.Get("X-Foo-Bar"))
				assert.Empty(t, headers.Get("Host"))
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
		"upstream changes are applied": {
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Foo-Bar", "incoming")
				req.Header.Set("Cookie", "foo=bar")
			},
			updateContext: func(t *testing.T, ctx *requestContext) {
				t.Helper()

				ctx.AddHeader("X-Foo-Bar", "from-heimdall")
				ctx.SetCookie("bar", "foo")
			},
			assert: func(t *testing.T, _ *requestContext, headers http.Header) {
				t.Helper()

				assert.Equal(t, []string{"from-heimdall"}, headers.Values("X-Foo-Bar"))
				assert.Contains(t, headers.Get("Cookie"), "foo=bar")
				assert.Contains(t, headers.Get("Cookie"), "bar=foo")
			},
		},
		"snapshot is detached": {
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Foo-Bar", "bar")
			},
			assert: func(t *testing.T, ctx *requestContext, headers http.Header) {
				t.Helper()

				headers.Set("X-Foo-Bar", "changed")

				assert.Equal(t, "bar", ctx.HeaderSnapshot().Get("X-Foo-Bar"))
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://foo.bar/test", nil)

			if tc.configureRequest != nil {
				tc.configureRequest(t, req)
			}

			ctx := &requestContext{RequestContext: requestcontext.New()}
			ctx.Init(httptest.NewRecorder(), req, nil)
			ctx.PrepareUpstreamRequest(nil)

			if tc.updateContext != nil {
				tc.updateContext(t, ctx)
			}

			// WHEN
			headers := ctx.HeaderSnapshot()

			// THEN
			tc.assert(t, ctx, headers)
		})
	}
}

func TestRequestContextReplaceHeaders(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		headers  http.Header
		expected http.Header
	}{
		"headers are replaced": {
			headers: http.Header{
				"X-Foo-Bar": []string{"baz"},
				"Host":      []string{"bar.foo"},
			},
			expected: http.Header{
				"X-Foo-Bar": []string{"baz"},
			},
		},
		"headers are replaced with empty headers": {
			headers:  nil,
			expected: http.Header{},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://foo.bar/test", nil)
			req.Header.Set("X-Original", "original")

			ctx := &requestContext{RequestContext: requestcontext.New()}
			ctx.Init(httptest.NewRecorder(), req, nil)
			ctx.PrepareUpstreamRequest(nil)

			ctx.AddHeader("X-From-Heimdall", "foo")
			ctx.SetCookie("foo", "bar")

			// WHEN
			ctx.ReplaceHeaders(tc.headers)

			// THEN
			assert.Empty(t, ctx.UpstreamHeaders())
			assert.Empty(t, ctx.UpstreamCookies())
			assert.Equal(t, tc.expected, ctx.HeaderSnapshot())
		})
	}
}
