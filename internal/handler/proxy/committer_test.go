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
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

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

func TestCommitterConcurrentIsolation(t *testing.T) {
	t.Parallel()

	// GIVEN
	type requestSnapshot struct {
		marker  string
		url     string
		host    string
		headers http.Header
	}

	type commitResult struct {
		marker string
		err    error
	}

	errA := errors.New("upstream A failed")
	errB := errors.New("upstream B failed")

	requestEntered := make(chan requestSnapshot, 2)
	releaseRequest := make(chan struct{})
	commitDone := make(chan commitResult, 2)

	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() {
			close(releaseRequest)
		})
	}
	defer release()

	rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		marker := req.Header.Get("X-Invocation")

		requestEntered <- requestSnapshot{
			marker:  marker,
			url:     req.URL.String(),
			host:    req.Host,
			headers: req.Header.Clone(),
		}

		<-releaseRequest

		switch marker {
		case "a":
			return nil, errA
		case "b":
			return nil, errB
		default:
			return nil, assert.AnError
		}
	})

	committer := newCommitter(rt)
	cf := newContextFactory()

	reqA := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"https://client-a.example/request-a",
		nil,
	)
	reqA.RemoteAddr = "192.0.2.10:1234"

	ctxA := cf.Create(reqA)
	defer cf.Destroy(ctxA)

	targetURLA, err := url.Parse("https://upstream-a.example/target-a?foo=a")
	require.NoError(t, err)

	targetA := mocks.NewUpstreamTargetMock(t)
	targetA.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
		*targetURL = *targetURLA
	})
	targetA.EXPECT().ForwardHostHeader().Return(false)

	ctxA.PrepareUpstreamView(targetA)
	ctxA.UpstreamRequest().SetHeader("X-Invocation", "a")

	reqB := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"http://client-b.example/request-b",
		nil,
	)
	reqB.RemoteAddr = "198.51.100.20:4321"

	ctxB := cf.Create(reqB)
	defer cf.Destroy(ctxB)

	targetURLB, err := url.Parse("http://upstream-b.example/target-b?foo=b")
	require.NoError(t, err)

	targetB := mocks.NewUpstreamTargetMock(t)
	targetB.EXPECT().ApplyTo(mock.Anything).Run(func(targetURL *url.URL) {
		*targetURL = *targetURLB
	})
	targetB.EXPECT().ForwardHostHeader().Return(false)

	ctxB.PrepareUpstreamView(targetB)
	ctxB.UpstreamRequest().SetHeader("X-Invocation", "b")

	rwA := httptest.NewRecorder()
	rwB := httptest.NewRecorder()

	// WHEN
	go func() {
		_, err := committer.Commit(rwA, ctxA)

		commitDone <- commitResult{marker: "a", err: err}
	}()

	go func() {
		_, err := committer.Commit(rwB, ctxB)

		commitDone <- commitResult{marker: "b", err: err}
	}()

	requests := make(map[string]requestSnapshot, 2)

	for range 2 {
		select {
		case req := <-requestEntered:
			requests[req.marker] = req
		case <-time.After(time.Second):
			require.FailNow(t, "requests did not concurrently enter round tripper")
		}
	}

	release()

	results := make(map[string]error, 2)

	for range 2 {
		select {
		case result := <-commitDone:
			results[result.marker] = result.err
		case <-time.After(time.Second):
			require.FailNow(t, "requests did not complete")
		}
	}

	// THEN
	require.Contains(t, requests, "a")
	require.Contains(t, requests, "b")

	assert.Equal(t, "https://upstream-a.example/target-a?foo=a", requests["a"].url)
	assert.Equal(t, "upstream-a.example", requests["a"].host)
	assert.Equal(t, "a", requests["a"].headers.Get("X-Invocation"))
	assert.Equal(t, "192.0.2.10", requests["a"].headers.Get("X-Forwarded-For"))
	assert.Equal(t, "client-a.example", requests["a"].headers.Get("X-Forwarded-Host"))
	assert.Equal(t, "https", requests["a"].headers.Get("X-Forwarded-Proto"))
	assert.Equal(
		t,
		`for=192.0.2.10;host="client-a.example";proto=https`,
		requests["a"].headers.Get("Forwarded"),
	)

	assert.Equal(t, "http://upstream-b.example/target-b?foo=b", requests["b"].url)
	assert.Equal(t, "upstream-b.example", requests["b"].host)
	assert.Equal(t, "b", requests["b"].headers.Get("X-Invocation"))
	assert.Equal(t, "198.51.100.20", requests["b"].headers.Get("X-Forwarded-For"))
	assert.Equal(t, "client-b.example", requests["b"].headers.Get("X-Forwarded-Host"))
	assert.Equal(t, "http", requests["b"].headers.Get("X-Forwarded-Proto"))
	assert.Equal(
		t,
		`for=198.51.100.20;host="client-b.example";proto=http`,
		requests["b"].headers.Get("Forwarded"),
	)

	require.ErrorIs(t, results["a"], pipeline.ErrCommunication)
	require.ErrorIs(t, results["a"], errA)
	require.NotErrorIs(t, results["a"], errB)

	require.ErrorIs(t, results["b"], pipeline.ErrCommunication)
	require.ErrorIs(t, results["b"], errB)
	require.NotErrorIs(t, results["b"], errA)
}
