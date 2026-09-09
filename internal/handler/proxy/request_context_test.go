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
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/handler/requestcontext"
	"github.com/dadrus/heimdall/internal/pipeline/mocks"
)

func TestRequestContextReset(t *testing.T) {
	t.Parallel()

	// GIVEN
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://foo.bar/test", nil)

	ctx := &requestContext{NetHTTPRequestContext: requestcontext.New()}
	ctx.Init(req)

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
	require.Nil(t, ctx.req)
	require.Empty(t, ctx.routingURL)
	require.Equal(t, upstreamSchemeUnknown, ctx.upstreamScheme)
	require.False(t, ctx.nativeGRPC)
	require.False(t, ctx.upgrade)
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
			ctx.Init(req)

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
			ctx.Init(req)

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

func TestRequestContextTransportClassification(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		contentType   string
		routingScheme string
		upgrade       bool
		nativeGRPC    bool
		scheme        upstreamScheme
	}{
		"ordinary http request": {
			routingScheme: "http",
			scheme:        upstreamSchemeHTTP,
		},
		"ordinary https request": {
			routingScheme: "https",
			scheme:        upstreamSchemeHTTPS,
		},
		"native gRPC request": {
			contentType:   "application/grpc+proto",
			routingScheme: "https",
			nativeGRPC:    true,
			scheme:        upstreamSchemeHTTPS,
		},
		"explicit h2c upstream": {
			routingScheme: "h2c",
			scheme:        upstreamSchemeH2C,
		},
		"upgrade request": {
			routingScheme: "https",
			upgrade:       true,
			scheme:        upstreamSchemeHTTPS,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://foo.bar/test", nil)
			if len(tc.contentType) != 0 {
				req.Header.Set("Content-Type", tc.contentType)
			}

			if tc.upgrade {
				req.Header.Set("Connection", "Upgrade")
				req.Header.Set("Upgrade", "websocket")
			}

			ctx := &requestContext{NetHTTPRequestContext: requestcontext.New()}
			ctx.Init(req)

			target := mocks.NewUpstreamTargetMock(t)
			target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
				targetURL.Scheme = tc.routingScheme
				targetURL.Host = "upstream.local"
			})
			target.EXPECT().ForwardHostHeader().Return(false)

			ctx.PrepareUpstreamView(target)
			proxyReq := &httputil.ProxyRequest{
				In:  req,
				Out: req.Clone(t.Context()),
			}

			// WHEN
			ctx.rewriteRequest(proxyReq)

			// THEN
			assert.Equal(t, tc.nativeGRPC, ctx.nativeGRPC)
			assert.Equal(t, tc.upgrade, ctx.upgrade)
			assert.Equal(t, tc.scheme, ctx.upstreamScheme)
		})
	}
}

func TestRequestContextRewriteRequestNormalizesH2C(t *testing.T) {
	t.Parallel()

	// GIVEN
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://foo.bar/test", nil)
	ctx := &requestContext{NetHTTPRequestContext: requestcontext.New()}
	ctx.Init(req)

	target := mocks.NewUpstreamTargetMock(t)
	target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
		targetURL.Scheme = "h2c"
		targetURL.Host = "upstream.local"
	})
	target.EXPECT().ForwardHostHeader().Return(false)

	ctx.PrepareUpstreamView(target)
	proxyReq := &httputil.ProxyRequest{
		In:  req,
		Out: req.Clone(t.Context()),
	}

	// WHEN
	ctx.rewriteRequest(proxyReq)

	// THEN
	assert.Equal(t, "h2c", ctx.routingURL.Scheme)
	assert.Equal(t, upstreamSchemeH2C, ctx.upstreamScheme)
	assert.Equal(t, "http", proxyReq.Out.URL.Scheme)
	assert.Equal(t, "upstream.local", proxyReq.Out.URL.Host)
}

func TestRequestContextHostMutationDoesNotChangeURL(t *testing.T) {
	t.Parallel()

	// GIVEN
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://foo.bar/test", nil)

	ctx := &requestContext{NetHTTPRequestContext: requestcontext.New()}
	ctx.Init(req)

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
			ctx.Init(req)
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
		httptest.NewRequestWithContext(
			context.TODO(),
			http.MethodGet,
			"https://foo.bar/test",
			nil,
		),
	)

	orig := ctx.Context()

	// WHEN
	actual := ctx.WithParent(t.Context())

	// THEN
	assert.Same(t, ctx, actual)
	assert.NotEqual(t, orig, ctx.Context())
	assert.Equal(t, t.Context(), ctx.Context())
}
