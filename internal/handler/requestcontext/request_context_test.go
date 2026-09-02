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

package requestcontext

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/pipeline"
)

func TestRequestClientIPs(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		configureRequest func(t *testing.T, req *http.Request)
		assert           func(t *testing.T, ips []string)
	}{
		"neither Forwarded, not X-Forwarded-For headers are present": {
			func(t *testing.T, _ *http.Request) { t.Helper() },
			func(t *testing.T, ips []string) {
				t.Helper()

				require.Len(t, ips, 1)
				assert.Contains(t, ips, "192.0.2.1")
			},
		},
		"only Forwarded header is present": {
			func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("Forwarded", "proto=http;for=127.0.0.1, proto=https;for=192.168.12.125")
			},
			func(t *testing.T, ips []string) {
				t.Helper()

				require.Len(t, ips, 3)

				assert.Equal(t, "127.0.0.1", ips[0])
				assert.Equal(t, "192.168.12.125", ips[1])
				assert.Equal(t, "192.0.2.1", ips[2])
			},
		},
		"only X-Forwarded-For header is present": {
			func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-For", "127.0.0.1, 192.168.12.125")
			},
			func(t *testing.T, ips []string) {
				t.Helper()

				require.Len(t, ips, 3)

				assert.Equal(t, "127.0.0.1", ips[0])
				assert.Equal(t, "192.168.12.125", ips[1])
				assert.Equal(t, "192.0.2.1", ips[2])
			},
		},
		"X-Forwarded-For appears multiple times": {
			func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Add("X-Forwarded-For", "127.0.0.1")
				req.Header.Add("X-Forwarded-For", "192.168.12.125")
			},
			func(t *testing.T, ips []string) {
				t.Helper()

				require.Len(t, ips, 3)

				assert.Equal(t, "127.0.0.1", ips[0])
				assert.Equal(t, "192.168.12.125", ips[1])
				assert.Equal(t, "192.0.2.1", ips[2])
			},
		},
		"Forwarded and X-Forwarded-For headers are present": {
			func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-For", "127.0.0.2, 192.168.12.126")
				req.Header.Set("Forwarded", "proto=http;for=127.0.0.3, proto=http;for=192.168.12.127")
			},
			func(t *testing.T, ips []string) {
				t.Helper()

				require.Len(t, ips, 3)

				assert.Equal(t, "127.0.0.3", ips[0])
				assert.Equal(t, "192.168.12.127", ips[1])
				assert.Equal(t, "192.0.2.1", ips[2])
			},
		},
		"Forwarded appears multiple times": {
			func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Add("Forwarded", "proto=http;for=127.0.0.1")
				req.Header.Add("Forwarded", "proto=https;for=192.168.12.125")
			},
			func(t *testing.T, ips []string) {
				t.Helper()

				require.Len(t, ips, 3)

				assert.Equal(t, "127.0.0.1", ips[0])
				assert.Equal(t, "192.168.12.125", ips[1])
				assert.Equal(t, "192.0.2.1", ips[2])
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			req := httptest.NewRequestWithContext(t.Context(), http.MethodHead, "https://foo.bar/test", nil)
			tc.configureRequest(t, req)

			rc := New()

			// WHEN
			rc.Init(req)

			// THEN
			tc.assert(t, rc.hmdlReq.ClientIPAddresses)
		})
	}
}

func TestRequestContextRequestHeaders(t *testing.T) {
	t.Parallel()

	// GIVEN
	req := httptest.NewRequestWithContext(t.Context(), http.MethodHead, "https://FoO.Baz/test", nil)
	req.Header.Set("X-Foo-Bar", "foo")
	req.Header.Add("X-Foo-Bar", "bar")

	ctx := New()
	ctx.Init(req)

	// WHEN
	headers := ctx.Request().Headers()

	// THEN
	require.Len(t, headers, 2)
	assert.Equal(t, "foo,bar", headers["X-Foo-Bar"])
	assert.Equal(t, "foo.baz", headers["Host"])
}

func TestRequestContextUpstreamRequest(t *testing.T) {
	t.Parallel()

	// GIVEN
	ctx := New()
	ctx.Init(httptest.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"https://foo.bar/test",
		nil,
	))

	// WHEN
	upstreamRequest := ctx.UpstreamRequest()

	// THEN
	assert.Nil(t, upstreamRequest)
}

func TestRequestContextMethod(t *testing.T) {
	t.Parallel()

	// GIVEN
	ctx := New()
	ctx.Init(httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPatch,
		"https://foo.bar/test",
		nil,
	))

	// WHEN
	method := ctx.Method()

	// THEN
	assert.Equal(t, http.MethodPatch, method)
}

func TestRequestContextURL(t *testing.T) {
	t.Parallel()

	// GIVEN
	ctx := New()
	ctx.Init(httptest.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"https://foo.bar/test?foo=bar",
		nil,
	))

	// WHEN
	upstreamURL := ctx.URL()

	// THEN
	assert.Equal(t, "https", upstreamURL.Scheme)
	assert.Equal(t, "foo.bar", upstreamURL.Host)
	assert.Equal(t, "/test", upstreamURL.Path)
	assert.Equal(t, "foo=bar", upstreamURL.RawQuery)

	upstreamURL.Host = "changed.local"
	upstreamURL.Path = "/changed"

	assert.Equal(t, "foo.bar", ctx.URL().Host)
	assert.Equal(t, "/test", ctx.URL().Path)

	ctx.SetHeader("Host", "bar.foo")

	assert.Equal(t, "bar.foo", ctx.URL().Host)
	assert.Equal(t, "foo.bar", ctx.Request().URL.Host)
}

func TestRequestContextAddHeader(t *testing.T) {
	t.Parallel()

	// GIVEN
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://foo.bar/test", nil)
	req.Header.Set("X-Foo", "incoming")

	ctx := New()
	ctx.Init(req)

	// WHEN
	ctx.AddHeader("X-Foo", "first")
	ctx.AddHeader("X-Foo", "second")
	ctx.AddHeader("Host", "bar.foo")

	// THEN
	assert.Equal(t, []string{"first", "second"}, ctx.Headers().Values("X-Foo"))
	assert.Equal(t, []string{"bar.foo"}, ctx.Headers().Values("Host"))
	assert.Equal(t, "bar.foo", ctx.URL().Host)

	assert.Equal(t, "incoming", ctx.Request().Header("X-Foo"))
	assert.Equal(t, "foo.bar", ctx.Request().URL.Host)
}

func TestRequestContextSetHeader(t *testing.T) {
	t.Parallel()

	// GIVEN
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://foo.bar/test", nil)
	req.Header.Set("X-Foo", "incoming")

	ctx := New()
	ctx.Init(req)
	ctx.AddHeader("X-Foo", "first")
	ctx.AddHeader("X-Foo", "second")

	// WHEN
	ctx.SetHeader("X-Foo", "replaced")
	ctx.SetHeader("Host", "bar.foo")

	// THEN
	assert.Equal(t, []string{"replaced"}, ctx.Headers().Values("X-Foo"))
	assert.Equal(t, []string{"bar.foo"}, ctx.Headers().Values("Host"))
	assert.Equal(t, "bar.foo", ctx.URL().Host)

	assert.Equal(t, "incoming", ctx.Request().Header("X-Foo"))
	assert.Equal(t, "foo.bar", ctx.Request().URL.Host)
}

func TestRequestContextSetCookie(t *testing.T) {
	t.Parallel()

	// GIVEN
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://foo.bar/test", nil)
	req.Header.Add("Cookie", "foo=old; session=abc")
	req.Header.Add("Cookie", "another=x; foo=older")

	ctx := New()
	ctx.Init(req)

	// WHEN
	ctx.SetCookie("foo", "new")

	// THEN
	require.Len(t, ctx.Headers().Values("Cookie"), 1)
	assert.Equal(t, "session=abc; another=x; foo=new", ctx.Headers().Get("Cookie"))

	ctx.SetCookie("session", "changed")

	require.Len(t, ctx.Headers().Values("Cookie"), 1)
	assert.Equal(t, "another=x; foo=new; session=changed", ctx.Headers().Get("Cookie"))
	assert.Equal(t, "old", ctx.Request().Cookie("foo"))
	assert.Equal(t, "abc", ctx.Request().Cookie("session"))
}

func TestRequestContextHeaders(t *testing.T) {
	t.Parallel()

	// GIVEN
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://foo.bar/test", nil)
	req.Header.Set("Host", "spoofed")
	req.Header.Set("X-Foo", "incoming")
	req.Header.Set("X-Removed", "remove-me")
	req.Header.Set("Cookie", "foo=bar")

	ctx := New()
	ctx.Init(req)
	ctx.AddHeader("X-Foo", "from-heimdall")
	ctx.SetHeader("X-Set", "set-by-heimdall")
	ctx.SetCookie("bar", "foo")
	ctx.upstreamHeaders["X-Removed"] = nil

	// WHEN
	headers := ctx.Headers()

	// THEN
	assert.Equal(t, []string{"from-heimdall"}, headers.Values("X-Foo"))
	assert.Equal(t, "set-by-heimdall", headers.Get("X-Set"))
	assert.Equal(t, "foo=bar; bar=foo", headers.Get("Cookie"))
	assert.Equal(t, "foo.bar", headers.Get("Host"))
	assert.Empty(t, headers.Values("X-Removed"))

	headers.Set("X-Foo", "changed")
	headers.Set("Host", "changed.local")
	headers.Set("Cookie", "changed=true")

	current := ctx.Headers()

	assert.Equal(t, []string{"from-heimdall"}, current.Values("X-Foo"))
	assert.Equal(t, "foo.bar", current.Get("Host"))
	assert.Equal(t, "foo=bar; bar=foo", current.Get("Cookie"))

	assert.Equal(t, "incoming", ctx.Request().Header("X-Foo"))
	assert.Equal(t, "foo.bar", ctx.Request().URL.Host)
	assert.Equal(t, "bar", ctx.Request().Cookie("foo"))
}

func TestRequestContextHeader(t *testing.T) {
	t.Parallel()

	// GIVEN
	req := httptest.NewRequestWithContext(t.Context(), http.MethodHead, "https://Foo.bar/test", nil)
	req.Header.Set("X-Foo-Bar", "foo")
	req.Header.Add("X-Foo-Bar", "bar")
	req.Host = "Bar.foo"

	ctx := New()
	ctx.Init(req)

	// WHEN
	xFooBarValue := ctx.Request().Header("X-Foo-Bar")
	hostValue := ctx.Request().Header("Host")
	emptyValue := ctx.Request().Header("X-Not-Present")

	// THEN
	assert.Equal(t, "foo,bar", xFooBarValue)
	assert.Equal(t, "bar.foo", hostValue)
	assert.Empty(t, emptyValue)
}

func TestRequestContextCookie(t *testing.T) {
	t.Parallel()

	// GIVEN
	req := httptest.NewRequestWithContext(t.Context(), http.MethodHead, "https://foo.bar/test", nil)
	req.Header.Set("Cookie", "foo=bar; bar=baz")

	ctx := New()
	ctx.Init(req)

	// WHEN
	value1 := ctx.Request().Cookie("bar")
	value2 := ctx.Request().Cookie("baz")

	// THEN
	assert.Equal(t, "baz", value1)
	assert.Empty(t, value2)
}

func TestRequestContextBody(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		ct     string
		body   io.Reader
		expect any
	}{
		"No body": {
			ct:     "empty",
			body:   nil,
			expect: "",
		},
		"Empty body": {
			ct:     "empty",
			body:   bytes.NewBufferString(""),
			expect: "",
		},
		"Wrong content type": {
			ct:     "application/json",
			body:   bytes.NewBufferString("foo: bar"),
			expect: "foo: bar",
		},
		"x-www-form-urlencoded encoded": {
			ct:     "application/x-www-form-urlencoded; charset=utf-8",
			body:   bytes.NewBufferString("content=heimdall"),
			expect: map[string]any{"content": []string{"heimdall"}},
		},
		"json encoded": {
			ct:     "application/json; charset=utf-8",
			body:   bytes.NewBufferString(`{ "content": "heimdall" }`),
			expect: map[string]any{"content": "heimdall"},
		},
		"json encoded array": {
			ct:     "application/json; charset=utf-8",
			body:   bytes.NewBufferString(`[{"content": "heimdall"}]`),
			expect: []any{map[string]any{"content": "heimdall"}},
		},
		"json encoded scalar string": {
			ct:     "application/json; charset=utf-8",
			body:   bytes.NewBufferString(`"heimdall"`),
			expect: "heimdall",
		},
		"json encoded scalar number": {
			ct:     "application/json; charset=utf-8",
			body:   bytes.NewBufferString(`42`),
			expect: float64(42),
		},
		"json encoded scalar bool": {
			ct:     "application/json; charset=utf-8",
			body:   bytes.NewBufferString(`true`),
			expect: true,
		},
		"json encoded null": {
			ct:     "application/json; charset=utf-8",
			body:   bytes.NewBufferString(`null`),
			expect: nil,
		},
		"yaml encoded": {
			ct:     "application/yaml; charset=utf-8",
			body:   bytes.NewBufferString("content: heimdall"),
			expect: map[string]any{"content": "heimdall"},
		},
		"yaml encoded sequence": {
			ct:     "application/yaml; charset=utf-8",
			body:   bytes.NewBufferString("- content: heimdall\n"),
			expect: []any{map[string]any{"content": "heimdall"}},
		},
		"yaml encoded scalar": {
			ct:     "application/yaml; charset=utf-8",
			body:   bytes.NewBufferString("heimdall\n"),
			expect: "heimdall",
		},
		"plain text": {
			ct:     "text/plain",
			body:   bytes.NewBufferString("content=heimdall"),
			expect: "content=heimdall",
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://foo.bar/test", tc.body)
			req.Header.Set("Content-Type", tc.ct)

			ctx := New()
			ctx.Init(req)

			// WHEN
			data := ctx.Request().Body()

			// THEN
			assert.Equal(t, tc.expect, data)
		})
	}
}

func TestRequestContextRawBody(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		body     io.Reader
		prepare  func(t *testing.T, ctx *RequestContext)
		expected string
	}{
		"No body": {
			expected: "",
		},
		"Body present": {
			body:     bytes.NewBufferString("content=heimdall"),
			expected: "content=heimdall",
		},
		"Body was already requested": {
			body: bytes.NewBufferString("content=heimdall"),
			prepare: func(t *testing.T, ctx *RequestContext) {
				t.Helper()

				body, err := ctx.RawBody()
				require.NoError(t, err)

				_, err = io.ReadAll(body)
				require.NoError(t, err)
				require.NoError(t, body.Close())
			},
			expected: "content=heimdall",
		},
		"Body was already decoded": {
			body: bytes.NewBufferString("content=heimdall"),
			prepare: func(t *testing.T, ctx *RequestContext) {
				t.Helper()

				_ = ctx.Body()
			},
			expected: "content=heimdall",
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://foo.bar/test", tc.body)

			ctx := New()
			ctx.Init(req)

			if tc.prepare != nil {
				tc.prepare(t, ctx)
			}

			// WHEN
			body, err := ctx.RawBody()

			// THEN
			require.NoError(t, err)
			require.NotNil(t, body)

			data, err := io.ReadAll(body)
			require.NoError(t, err)
			require.NoError(t, body.Close())

			assert.Equal(t, tc.expected, string(data))

			requestBody, err := io.ReadAll(req.Body)
			require.NoError(t, err)

			assert.Equal(t, tc.expected, string(requestBody))
		})
	}
}

func TestRequestContextRequestURLCaptures(t *testing.T) {
	t.Parallel()

	// GIVEN
	ctx := New()
	ctx.Init(httptest.NewRequestWithContext(t.Context(), http.MethodHead, "https://foo.bar/test", nil))

	ctx.Request().URL.Captures = map[string]string{"a": "b"}

	// WHEN
	captures := ctx.Request().URL.Captures
	require.Len(t, captures, 1)
	assert.Equal(t, "b", captures["a"])
}

func TestRequestContextReset(t *testing.T) {
	t.Parallel()

	// GIVEN
	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodHead,
		"https://foo.bar/test",
		bytes.NewBufferString(`{ "content": "heimdall" }`),
	)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	ctx := New()
	ctx.Init(req)
	ctx.Request().URL.Captures = map[string]string{"a": "b"}
	ctx.SetError(assert.AnError)
	_ = ctx.Body()
	ctx.Outputs()["a"] = pipeline.NewResult("b")
	ctx.SetCookie("foo", "bar")
	ctx.SetHeader("bar", "foo")
	_ = ctx.Request().Headers()
	_ = ctx.Headers()

	// WHEN
	ctx.Reset()

	// THEN
	require.Nil(t, ctx.savedBody)
	require.Nil(t, ctx.rawBody)
	require.NoError(t, ctx.err)
	require.Nil(t, ctx.req)
	require.NotNil(t, ctx.outputs)
	require.Empty(t, ctx.outputs)
	require.NotNil(t, ctx.headers)
	require.Empty(t, ctx.headers)
	require.NotNil(t, ctx.upstreamHeaders)
	require.Empty(t, ctx.upstreamHeaders)
	require.NotNil(t, ctx.hmdlReq)
	require.NotNil(t, ctx.hmdlReq.URL)
	require.Empty(t, ctx.hmdlReq.URL.URL)
	require.Empty(t, ctx.hmdlReq.Method)
	require.NotNil(t, ctx.hmdlReq.URL.Captures)
	require.Empty(t, ctx.hmdlReq.URL.Captures)
	require.NotNil(t, ctx.hmdlReq.ClientIPAddresses)
	require.Empty(t, ctx.hmdlReq.ClientIPAddresses)
	require.Equal(t, 10, cap(ctx.hmdlReq.ClientIPAddresses))
}

func TestRequestContextWithParent(t *testing.T) {
	t.Parallel()

	// GIVEN
	ctx := New()
	ctx.Init(httptest.NewRequestWithContext(
		t.Context(),
		http.MethodHead,
		"https://foo.bar/test",
		nil,
	))

	orig := ctx.Context()
	newParent := context.Background()

	ctx.WithParent(newParent)

	assert.NotEqual(t, orig, ctx.ctx)
	assert.Equal(t, newParent, ctx.ctx)
}
