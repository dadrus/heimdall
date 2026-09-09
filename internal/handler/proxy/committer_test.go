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
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/pipeline/mocks"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestCommitterCommit(t *testing.T) {
	t.Parallel()

	cf := newContextFactory()

	for uc, tc := range map[string]struct {
		useIPv6      bool
		headers      http.Header
		roundTripper http.RoundTripper
		setup        func(*testing.T, *requestContext, *mocks.UpstreamTargetMock, *url.URL)
		assert       func(*testing.T, error, *http.Request)
	}{
		"no upstream target": {
			setup: func(t *testing.T, _ *requestContext, _ *mocks.UpstreamTargetMock, _ *url.URL) {
				t.Helper()
			},
			assert: func(t *testing.T, err error, req *http.Request) {
				t.Helper()

				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.Nil(t, req)
			},
		},
		"no headers set, ipv6 is used": {
			useIPv6: true,
			setup: func(t *testing.T, ctx *requestContext, target *mocks.UpstreamTargetMock, upstreamURL *url.URL) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = *upstreamURL
				})
				target.EXPECT().ForwardHostHeader().Return(false)

				ctx.PrepareUpstreamView(target)
			},
			assert: func(t *testing.T, err error, req *http.Request) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, req)

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
			useIPv6: true,
			headers: http.Header{
				"X-Forwarded-Proto":  []string{"https"},
				"X-Forwarded-Host":   []string{"bar.foo"},
				"X-Forwarded-Path":   []string{"/foobar"},
				"X-Forwarded-Uri":    []string{"/barfoo?foo=bar"},
				"X-Forwarded-Method": []string{http.MethodPatch},
				"X-Forwarded-For":    []string{"127.0.0.2, 192.168.12.126"},
				"Forwarded":          []string{"proto=http;for=127.0.0.3, proto=http;for=192.168.12.127"},
			},
			setup: func(t *testing.T, ctx *requestContext, target *mocks.UpstreamTargetMock, upstreamURL *url.URL) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = *upstreamURL
				})
				target.EXPECT().ForwardHostHeader().Return(false)

				ctx.PrepareUpstreamView(target)
			},
			assert: func(t *testing.T, err error, req *http.Request) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, req)

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
			headers: http.Header{
				"X-Forwarded-For": []string{"127.0.0.2", "192.168.12.126"},
				"Forwarded":       []string{"proto=http;for=127.0.0.3", "proto=https;for=192.168.12.127"},
			},
			setup: func(t *testing.T, ctx *requestContext, target *mocks.UpstreamTargetMock, upstreamURL *url.URL) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = *upstreamURL
				})
				target.EXPECT().ForwardHostHeader().Return(false)

				ctx.PrepareUpstreamView(target)
			},
			assert: func(t *testing.T, err error, req *http.Request) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, req)

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
			headers: http.Header{
				"X-Forwarded-Method": []string{http.MethodPost},
				"Forwarded":          []string{"proto=http;for=127.0.0.3, proto=http;for=192.168.12.127"},
			},
			setup: func(t *testing.T, ctx *requestContext, target *mocks.UpstreamTargetMock, upstreamURL *url.URL) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = *upstreamURL
				})
				target.EXPECT().ForwardHostHeader().Return(false)

				ctx.PrepareUpstreamView(target)
			},
			assert: func(t *testing.T, err error, req *http.Request) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, req)

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
			headers: http.Header{
				"X-Foo-Bar": []string{"bar", "foo"},
				"X-Bar":     []string{"bar"},
			},
			setup: func(t *testing.T, ctx *requestContext, target *mocks.UpstreamTargetMock, upstreamURL *url.URL) {
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
			assert: func(t *testing.T, err error, req *http.Request) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, req)

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
			headers: http.Header{
				"X-Foo-Bar": []string{"bar", "foo"},
				"X-Bar":     []string{"bar"},
			},
			setup: func(t *testing.T, ctx *requestContext, target *mocks.UpstreamTargetMock, upstreamURL *url.URL) {
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
			assert: func(t *testing.T, err error, req *http.Request) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, req)

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
			setup: func(t *testing.T, ctx *requestContext, target *mocks.UpstreamTargetMock, upstreamURL *url.URL) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = *upstreamURL
				})
				target.EXPECT().ForwardHostHeader().Return(false)

				ctx.PrepareUpstreamView(target)
				ctx.UpstreamRequest().AddHeader("Host", "bar.foo")
			},
			assert: func(t *testing.T, err error, req *http.Request) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, req)

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
			headers: http.Header{
				"X-Forwarded-Proto": []string{"http"},
			},
			setup: func(t *testing.T, ctx *requestContext, target *mocks.UpstreamTargetMock, upstreamURL *url.URL) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = *upstreamURL
				})
				target.EXPECT().ForwardHostHeader().Return(false)

				ctx.PrepareUpstreamView(target)
			},
			assert: func(t *testing.T, err error, req *http.Request) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, req)

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
			headers: http.Header{
				"X-Forwarded-Host": []string{"bar.foo"},
			},
			setup: func(t *testing.T, ctx *requestContext, target *mocks.UpstreamTargetMock, upstreamURL *url.URL) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = *upstreamURL
				})
				target.EXPECT().ForwardHostHeader().Return(true)

				ctx.PrepareUpstreamView(target)
			},
			assert: func(t *testing.T, err error, req *http.Request) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, req)

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
			headers: http.Header{
				"X-Forwarded-For": []string{"172.2.34.1"},
			},
			setup: func(t *testing.T, ctx *requestContext, target *mocks.UpstreamTargetMock, upstreamURL *url.URL) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = *upstreamURL
				})
				target.EXPECT().ForwardHostHeader().Return(false)

				ctx.PrepareUpstreamView(target)
			},
			assert: func(t *testing.T, err error, req *http.Request) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, req)

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
			headers: http.Header{
				"X-Foo-Bar": []string{"bar"},
			},
			setup: func(t *testing.T, ctx *requestContext, target *mocks.UpstreamTargetMock, upstreamURL *url.URL) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = *upstreamURL
				})
				target.EXPECT().ForwardHostHeader().Return(false)

				ctx.PrepareUpstreamView(target)

				ctx.UpstreamRequest().SetHeader("X-Foo-Bar", "baz")
				ctx.UpstreamRequest().SetHeader("X-Set", "foo")
			},
			assert: func(t *testing.T, err error, req *http.Request) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, req)

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
		"TE containing trailers is normalized for upstream": {
			headers: http.Header{
				"Te": []string{"gzip, trailers"},
			},
			setup: func(t *testing.T, ctx *requestContext, target *mocks.UpstreamTargetMock, upstreamURL *url.URL) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = *upstreamURL
				})
				target.EXPECT().ForwardHostHeader().Return(false)

				ctx.PrepareUpstreamView(target)
			},
			assert: func(t *testing.T, err error, req *http.Request) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, req)

				assert.Equal(t, "trailers", req.Header.Get("Te"))
			},
		},
		"TE without trailers is dropped for upstream": {
			headers: http.Header{
				"Te": []string{"gzip"},
			},
			setup: func(t *testing.T, ctx *requestContext, target *mocks.UpstreamTargetMock, upstreamURL *url.URL) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = *upstreamURL
				})
				target.EXPECT().ForwardHostHeader().Return(false)

				ctx.PrepareUpstreamView(target)
			},
			assert: func(t *testing.T, err error, req *http.Request) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, req)

				assert.Empty(t, req.Header.Get("Te"))
			},
		},
		"TE trailers survives Connection TE": {
			headers: http.Header{
				"Connection": []string{"TE"},
				"Te":         []string{"trailers"},
			},
			setup: func(t *testing.T, ctx *requestContext, target *mocks.UpstreamTargetMock, upstreamURL *url.URL) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = *upstreamURL
				})
				target.EXPECT().ForwardHostHeader().Return(false)

				ctx.PrepareUpstreamView(target)
			},
			assert: func(t *testing.T, err error, req *http.Request) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, req)

				assert.Empty(t, req.Header.Get("Connection"))
				assert.Equal(t, "trailers", req.Header.Get("Te"))
			},
		},
		"proxying fails": {
			roundTripper: roundTripperFunc(func(_ *http.Request) (*http.Response, error) {
				return nil, assert.AnError
			}),
			setup: func(t *testing.T, ctx *requestContext, target *mocks.UpstreamTargetMock, upstreamURL *url.URL) {
				t.Helper()

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = *upstreamURL
				})
				target.EXPECT().ForwardHostHeader().Return(false)

				ctx.PrepareUpstreamView(target)
			},
			assert: func(t *testing.T, err error, req *http.Request) {
				t.Helper()

				require.ErrorIs(t, err, pipeline.ErrCommunication)
				require.ErrorIs(t, err, assert.AnError)
				require.NotErrorIs(t, err, pipeline.ErrRequestBodyTooLarge)
				require.Nil(t, req)
			},
		},
		"request body exceeds limit while proxying": {
			roundTripper: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				_, err := io.ReadAll(req.Body)

				return nil, err
			}),
			setup: func(t *testing.T, ctx *requestContext, target *mocks.UpstreamTargetMock, upstreamURL *url.URL) {
				t.Helper()

				ctx.req.Body = http.MaxBytesReader(
					httptest.NewRecorder(),
					ctx.req.Body,
					3,
				)
				ctx.req.ContentLength = -1

				target.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
					*targetURL = *upstreamURL
				})
				target.EXPECT().ForwardHostHeader().Return(false)

				ctx.PrepareUpstreamView(target)
			},
			assert: func(t *testing.T, err error, req *http.Request) {
				t.Helper()

				require.ErrorIs(t, err, pipeline.ErrRequestBodyTooLarge)
				require.NotErrorIs(t, err, pipeline.ErrCommunication)
				require.Nil(t, req)

				var maxBytesErr *http.MaxBytesError

				require.ErrorAs(t, err, &maxBytesErr)
				assert.Equal(t, int64(3), maxBytesErr.Limit)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			var upstreamReq *http.Request

			req := httptest.NewRequestWithContext(
				t.Context(),
				http.MethodGet,
				"https://foo.bar/test",
				bytes.NewBufferString("Ping"),
			)
			req.Header = tc.headers

			if tc.useIPv6 {
				req.RemoteAddr = "[a746:9bbd:955b:e17e:cede:9748:0bf5:f2ea]:1234"
			}

			rw := httptest.NewRecorder()

			srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
				upstreamReq = req
			}))
			defer srv.Close()

			targetURL, err := url.Parse(srv.URL)
			require.NoError(t, err)

			ctx := cf.Create(req)
			defer cf.Destroy(ctx)

			target := mocks.NewUpstreamTargetMock(t)
			tc.setup(t, ctx, target, targetURL)

			rt := tc.roundTripper
			if rt == nil {
				transport := http.DefaultTransport.(*http.Transport).Clone()
				defer transport.CloseIdleConnections()

				rt = transport
			}

			committer := newCommitter(rt)

			// WHEN
			_, err = committer.Commit(rw, ctx)

			// THEN
			tc.assert(t, err, upstreamReq)
		})
	}
}
