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
	"context"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/pipeline"
)

type testBodySource struct {
	body  []byte
	err   error
	calls int
}

func (s *testBodySource) ReadRawBody() ([]byte, error) {
	s.calls++

	return s.body, s.err
}

func newTestRequestContext(
	t *testing.T,
	method string,
	rawURL string,
	headers http.Header,
	body BodySource,
) *RequestContext {
	t.Helper()

	requestURL, err := url.Parse(rawURL)
	require.NoError(t, err)

	ctx := NewRequestContext()
	ctx.Init(Input{
		Context:    t.Context(),
		Method:     method,
		URL:        *requestURL,
		Headers:    headers,
		RemoteAddr: "192.0.2.1:1234",
		Body:       body,
	})

	return ctx
}

func TestRequestClientIPs(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		configureHeaders func(t *testing.T, headers http.Header)
		assert           func(t *testing.T, ips []string)
	}{
		"neither Forwarded, not X-Forwarded-For headers are present": {
			func(t *testing.T, _ http.Header) { t.Helper() },
			func(t *testing.T, ips []string) {
				t.Helper()

				require.Len(t, ips, 1)
				assert.Contains(t, ips, "192.0.2.1")
			},
		},
		"only Forwarded header is present": {
			func(t *testing.T, headers http.Header) {
				t.Helper()

				headers.Set("Forwarded", "proto=http;for=127.0.0.1, proto=https;for=192.168.12.125")
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
			func(t *testing.T, headers http.Header) {
				t.Helper()

				headers.Set("X-Forwarded-For", "127.0.0.1, 192.168.12.125")
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
			func(t *testing.T, headers http.Header) {
				t.Helper()

				headers.Add("X-Forwarded-For", "127.0.0.1")
				headers.Add("X-Forwarded-For", "192.168.12.125")
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
			func(t *testing.T, headers http.Header) {
				t.Helper()

				headers.Set("X-Forwarded-For", "127.0.0.2, 192.168.12.126")
				headers.Set("Forwarded", "proto=http;for=127.0.0.3, proto=http;for=192.168.12.127")
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
			func(t *testing.T, headers http.Header) {
				t.Helper()

				headers.Add("Forwarded", "proto=http;for=127.0.0.1")
				headers.Add("Forwarded", "proto=https;for=192.168.12.125")
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
			headers := make(http.Header)
			tc.configureHeaders(t, headers)

			// WHEN
			ips := requestClientIPs(nil, headers, "192.0.2.1:1234")

			// THEN
			tc.assert(t, ips)
		})
	}
}

func TestRequestContextRequestHeaders(t *testing.T) {
	t.Parallel()

	// GIVEN
	headers := make(http.Header)
	headers.Set("X-Foo-Bar", "foo")
	headers.Add("X-Foo-Bar", "bar")

	ctx := newTestRequestContext(t, http.MethodHead, "https://foo.baz/test", headers, nil)

	// WHEN
	actual := ctx.Request().Headers()

	// THEN
	require.Len(t, actual, 2)
	assert.Equal(t, "foo,bar", actual["X-Foo-Bar"])
	assert.Equal(t, "foo.baz", actual["Host"])
}

func TestRequestContextMethod(t *testing.T) {
	t.Parallel()

	// GIVEN
	ctx := newTestRequestContext(t, http.MethodPatch, "https://foo.bar/test", nil, nil)

	// WHEN
	method := ctx.Method()

	// THEN
	assert.Equal(t, http.MethodPatch, method)
}

func TestRequestContextURL(t *testing.T) {
	t.Parallel()

	// GIVEN
	ctx := newTestRequestContext(t, http.MethodGet, "https://foo.bar/test?foo=bar", nil, nil)

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

	assert.Equal(t, "foo.bar", ctx.URL().Host)
	assert.Equal(t, "bar.foo", ctx.Headers().Get("Host"))
	assert.Equal(t, "foo.bar", ctx.Request().URL.Host)
	assert.Equal(t, "foo.bar", ctx.Request().Header("Host"))
}

func TestRequestContextAddHeader(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		configureHeaders func(t *testing.T, headers http.Header)
		mutate           func(t *testing.T, ctx *RequestContext)
		assert           func(t *testing.T, ctx *RequestContext)
	}{
		"ordinary and Host headers are added": {
			configureHeaders: func(t *testing.T, headers http.Header) {
				t.Helper()

				headers.Set("X-Foo", "incoming")
			},
			mutate: func(t *testing.T, ctx *RequestContext) {
				t.Helper()

				ctx.AddHeader("X-Foo", "first")
				ctx.AddHeader("X-Foo", "second")
				ctx.AddHeader("Host", "bar.foo")
				ctx.AddHeader("hOsT", "baz.foo")
			},
			assert: func(t *testing.T, ctx *RequestContext) {
				t.Helper()

				assert.Equal(t, []string{"first", "second"}, ctx.Headers().Values("X-Foo"))
				assert.Equal(t, []string{"baz.foo"}, ctx.Headers().Values("Host"))
				assert.Equal(t, "foo.bar", ctx.URL().Host)

				assert.Equal(t, "incoming", ctx.Request().Header("X-Foo"))
				assert.Equal(t, "foo.bar", ctx.Request().Header("Host"))
				assert.Equal(t, "foo.bar", ctx.Request().URL.Host)
			},
		},
		"protected header is ignored": {
			mutate: func(t *testing.T, ctx *RequestContext) {
				t.Helper()

				ctx.AddHeader("X-Forwarded-Method", http.MethodDelete)
			},
			assert: func(t *testing.T, ctx *RequestContext) {
				t.Helper()

				assert.Empty(t, ctx.Headers().Get("X-Forwarded-Method"))
				assert.NotContains(t, ctx.UpstreamHeaders(), "X-Forwarded-Method")
			},
		},
		"connection-specific header is ignored": {
			configureHeaders: func(t *testing.T, headers http.Header) {
				t.Helper()

				headers.Set("Connection", "x-foo")
				headers.Set("X-Foo", "incoming")
			},
			mutate: func(t *testing.T, ctx *RequestContext) {
				t.Helper()

				ctx.AddHeader("X-Foo", "from-heimdall")
			},
			assert: func(t *testing.T, ctx *RequestContext) {
				t.Helper()

				assert.Equal(t, "incoming", ctx.Headers().Get("X-Foo"))
				assert.NotContains(t, ctx.UpstreamHeaders(), "X-Foo")
			},
		},
		"pseudo header is ignored": {
			mutate: func(t *testing.T, ctx *RequestContext) {
				t.Helper()

				ctx.AddHeader(":authority", "bar.foo")
			},
			assert: func(t *testing.T, ctx *RequestContext) {
				t.Helper()

				assert.NotContains(t, ctx.UpstreamHeaders(), ":authority")
				assert.Equal(t, "foo.bar", ctx.Headers().Get("Host"))
				assert.Equal(t, "foo.bar", ctx.Request().URL.Host)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			headers := make(http.Header)
			if tc.configureHeaders != nil {
				tc.configureHeaders(t, headers)
			}

			ctx := newTestRequestContext(t, http.MethodGet, "https://foo.bar/test", headers, nil)

			// WHEN
			tc.mutate(t, ctx)

			// THEN
			tc.assert(t, ctx)
		})
	}
}

func TestRequestContextSetHeader(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		configureHeaders func(t *testing.T, headers http.Header)
		prepareContext   func(t *testing.T, ctx *RequestContext)
		mutate           func(t *testing.T, ctx *RequestContext)
		assert           func(t *testing.T, ctx *RequestContext)
	}{
		"ordinary and Host headers are set": {
			configureHeaders: func(t *testing.T, headers http.Header) {
				t.Helper()

				headers.Set("X-Foo", "incoming")
			},
			prepareContext: func(t *testing.T, ctx *RequestContext) {
				t.Helper()

				ctx.AddHeader("X-Foo", "first")
				ctx.AddHeader("X-Foo", "second")
			},
			mutate: func(t *testing.T, ctx *RequestContext) {
				t.Helper()

				ctx.SetHeader("X-Foo", "replaced")
				ctx.SetHeader("Host", "bar.foo")
			},
			assert: func(t *testing.T, ctx *RequestContext) {
				t.Helper()

				assert.Equal(t, []string{"replaced"}, ctx.Headers().Values("X-Foo"))
				assert.Equal(t, []string{"bar.foo"}, ctx.Headers().Values("Host"))
				assert.Equal(t, "foo.bar", ctx.URL().Host)

				assert.Equal(t, "incoming", ctx.Request().Header("X-Foo"))
				assert.Equal(t, "foo.bar", ctx.Request().Header("Host"))
				assert.Equal(t, "foo.bar", ctx.Request().URL.Host)
			},
		},
		"protected header is ignored": {
			mutate: func(t *testing.T, ctx *RequestContext) {
				t.Helper()

				ctx.SetHeader("Content-Length", "42")
			},
			assert: func(t *testing.T, ctx *RequestContext) {
				t.Helper()

				assert.Empty(t, ctx.Headers().Get("Content-Length"))
				assert.NotContains(t, ctx.UpstreamHeaders(), "Content-Length")
			},
		},
		"connection-specific header is ignored": {
			configureHeaders: func(t *testing.T, headers http.Header) {
				t.Helper()

				headers.Set("Connection", "X-Foo")
				headers.Set("X-Foo", "incoming")
			},
			mutate: func(t *testing.T, ctx *RequestContext) {
				t.Helper()

				ctx.SetHeader("X-Foo", "from-heimdall")
			},
			assert: func(t *testing.T, ctx *RequestContext) {
				t.Helper()

				assert.Equal(t, "incoming", ctx.Headers().Get("X-Foo"))
				assert.NotContains(t, ctx.UpstreamHeaders(), "X-Foo")
			},
		},
		"pseudo header is ignored": {
			mutate: func(t *testing.T, ctx *RequestContext) {
				t.Helper()

				ctx.SetHeader(":path", "/changed")
			},
			assert: func(t *testing.T, ctx *RequestContext) {
				t.Helper()

				assert.NotContains(t, ctx.UpstreamHeaders(), ":path")
				assert.Equal(t, "/test", ctx.URL().Path)
				assert.Equal(t, "/test", ctx.Request().URL.Path)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			headers := make(http.Header)
			if tc.configureHeaders != nil {
				tc.configureHeaders(t, headers)
			}

			ctx := newTestRequestContext(t, http.MethodGet, "https://foo.bar/test", headers, nil)

			if tc.prepareContext != nil {
				tc.prepareContext(t, ctx)
			}

			// WHEN
			tc.mutate(t, ctx)

			// THEN
			tc.assert(t, ctx)
		})
	}
}

func TestRequestContextSetCookie(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		configureHeaders func(t *testing.T, headers http.Header)
		prepareContext   func(t *testing.T, ctx *RequestContext)
		mutate           func(t *testing.T, ctx *RequestContext)
		assert           func(t *testing.T, ctx *RequestContext)
	}{
		"cookie is set": {
			configureHeaders: func(t *testing.T, headers http.Header) {
				t.Helper()

				headers.Add("Cookie", "foo=old; session=abc")
				headers.Add("Cookie", "another=x; foo=older")
			},
			mutate: func(t *testing.T, ctx *RequestContext) {
				t.Helper()

				ctx.SetCookie("foo", "new")
			},
			assert: func(t *testing.T, ctx *RequestContext) {
				t.Helper()

				require.Len(t, ctx.Headers().Values("Cookie"), 1)
				assert.Equal(t, "session=abc; another=x; foo=new", ctx.Headers().Get("Cookie"))

				ctx.SetCookie("session", "changed")

				require.Len(t, ctx.Headers().Values("Cookie"), 1)
				assert.Equal(t, "another=x; foo=new; session=changed", ctx.Headers().Get("Cookie"))
				assert.Equal(t, "old", ctx.Request().Cookie("foo"))
				assert.Equal(t, "abc", ctx.Request().Cookie("session"))
			},
		},
		"cookie is set if no Cookie header is present": {
			mutate: func(t *testing.T, ctx *RequestContext) {
				t.Helper()

				ctx.SetCookie("foo", "bar")
			},
			assert: func(t *testing.T, ctx *RequestContext) {
				t.Helper()

				require.Len(t, ctx.Headers().Values("Cookie"), 1)
				assert.Equal(t, "foo=bar", ctx.Headers().Get("Cookie"))
				assert.Empty(t, ctx.Request().Header("Cookie"))
			},
		},
		"malformed Cookie header is not mutated": {
			configureHeaders: func(t *testing.T, headers http.Header) {
				t.Helper()

				headers.Set("Cookie", "foo=old; malformed; session=abc")
			},
			mutate: func(t *testing.T, ctx *RequestContext) {
				t.Helper()

				ctx.SetCookie("foo", "new")
			},
			assert: func(t *testing.T, ctx *RequestContext) {
				t.Helper()

				assert.Equal(t, "foo=old; malformed; session=abc", ctx.Headers().Get("Cookie"))
				assert.NotContains(t, ctx.UpstreamHeaders(), "Cookie")
			},
		},
		"malformed Cookie header in overlay is not mutated": {
			configureHeaders: func(t *testing.T, headers http.Header) {
				t.Helper()

				headers.Set("Cookie", "foo=old; session=abc")
			},
			prepareContext: func(t *testing.T, ctx *RequestContext) {
				t.Helper()

				ctx.upstreamHeaders.Set("Cookie", "foo=overlay; malformed")
			},
			mutate: func(t *testing.T, ctx *RequestContext) {
				t.Helper()

				ctx.SetCookie("foo", "new")
			},
			assert: func(t *testing.T, ctx *RequestContext) {
				t.Helper()

				assert.Equal(t, "foo=overlay; malformed", ctx.Headers().Get("Cookie"))
				assert.Equal(t, "foo=old; session=abc", ctx.Request().Header("Cookie"))
			},
		},
		"connection-specific Cookie header is not mutated": {
			configureHeaders: func(t *testing.T, headers http.Header) {
				t.Helper()

				headers.Set("Connection", "Cookie")
				headers.Set("Cookie", "foo=old; session=abc")
			},
			mutate: func(t *testing.T, ctx *RequestContext) {
				t.Helper()

				ctx.SetCookie("foo", "new")
			},
			assert: func(t *testing.T, ctx *RequestContext) {
				t.Helper()

				assert.Equal(t, "foo=old; session=abc", ctx.Headers().Get("Cookie"))
				assert.NotContains(t, ctx.UpstreamHeaders(), "Cookie")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			headers := make(http.Header)
			if tc.configureHeaders != nil {
				tc.configureHeaders(t, headers)
			}

			ctx := newTestRequestContext(t, http.MethodGet, "https://foo.bar/test", headers, nil)

			if tc.prepareContext != nil {
				tc.prepareContext(t, ctx)
			}

			// WHEN
			tc.mutate(t, ctx)

			// THEN
			tc.assert(t, ctx)
		})
	}
}

func TestRequestContextConnectionSpecificHeaders(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		configureHeaders func(t *testing.T, headers http.Header)
		expected         []string
	}{
		"no connection-specific headers": {},
		"connection-specific headers are initialized": {
			configureHeaders: func(t *testing.T, headers http.Header) {
				t.Helper()

				headers.Add("Connection", "X-Foo, x-bar")
				headers.Add("Connection", " X-Baz ")
			},
			expected: []string{"X-Foo", "X-Bar", "X-Baz"},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			headers := make(http.Header)
			if tc.configureHeaders != nil {
				tc.configureHeaders(t, headers)
			}

			ctx := newTestRequestContext(t, http.MethodGet, "https://foo.bar/test", headers, nil)

			// WHEN
			actual := make([]string, 0, len(tc.expected))
			for name := range ctx.ConnectionSpecificHeaders() {
				actual = append(actual, name)
			}

			// THEN
			assert.ElementsMatch(t, tc.expected, actual)
		})
	}
}

func TestRequestContextHeaders(t *testing.T) {
	t.Parallel()

	// GIVEN
	headers := make(http.Header)
	headers.Set("Host", "spoofed")
	headers.Set("X-Foo", "incoming")
	headers.Set("X-Removed", "remove-me")
	headers.Set("Cookie", "foo=bar")

	ctx := newTestRequestContext(t, http.MethodGet, "https://foo.bar/test", headers, nil)
	ctx.AddHeader("X-Foo", "from-heimdall")
	ctx.SetHeader("X-Set", "set-by-heimdall")
	ctx.SetCookie("bar", "foo")
	ctx.upstreamHeaders["X-Removed"] = nil

	// WHEN
	actual := ctx.Headers()

	// THEN
	assert.Equal(t, []string{"from-heimdall"}, actual.Values("X-Foo"))
	assert.Equal(t, "set-by-heimdall", actual.Get("X-Set"))
	assert.Equal(t, "foo=bar; bar=foo", actual.Get("Cookie"))
	assert.Equal(t, "foo.bar", actual.Get("Host"))
	assert.Empty(t, actual.Values("X-Removed"))

	actual.Set("X-Foo", "changed")
	actual.Set("Host", "changed.local")
	actual.Set("Cookie", "changed=true")

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
	headers := make(http.Header)
	headers.Set("X-Foo-Bar", "foo")
	headers.Add("X-Foo-Bar", "bar")

	ctx := newTestRequestContext(t, http.MethodHead, "https://bar.foo/test", headers, nil)

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
	headers := make(http.Header)
	headers.Set("Cookie", "foo=bar; bar=baz")

	ctx := newTestRequestContext(t, http.MethodHead, "https://foo.bar/test", headers, nil)

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
		body   string
		expect any
	}{
		"No body": {
			ct:     "empty",
			expect: "",
		},
		"Empty body": {
			ct:     "empty",
			body:   "",
			expect: "",
		},
		"Wrong content type": {
			ct:     "application/json",
			body:   "foo: bar",
			expect: "foo: bar",
		},
		"x-www-form-urlencoded encoded": {
			ct:     "application/x-www-form-urlencoded; charset=utf-8",
			body:   "content=heimdall",
			expect: map[string]any{"content": []string{"heimdall"}},
		},
		"json encoded": {
			ct:     "application/json; charset=utf-8",
			body:   `{ "content": "heimdall" }`,
			expect: map[string]any{"content": "heimdall"},
		},
		"json encoded array": {
			ct:     "application/json; charset=utf-8",
			body:   `[{"content": "heimdall"}]`,
			expect: []any{map[string]any{"content": "heimdall"}},
		},
		"json encoded scalar string": {
			ct:     "application/json; charset=utf-8",
			body:   `"heimdall"`,
			expect: "heimdall",
		},
		"json encoded scalar number": {
			ct:     "application/json; charset=utf-8",
			body:   `42`,
			expect: float64(42),
		},
		"json encoded scalar bool": {
			ct:     "application/json; charset=utf-8",
			body:   `true`,
			expect: true,
		},
		"json encoded null": {
			ct:     "application/json; charset=utf-8",
			body:   `null`,
			expect: nil,
		},
		"yaml encoded": {
			ct:     "application/yaml; charset=utf-8",
			body:   "content: heimdall",
			expect: map[string]any{"content": "heimdall"},
		},
		"yaml encoded sequence": {
			ct:     "application/yaml; charset=utf-8",
			body:   "- content: heimdall\n",
			expect: []any{map[string]any{"content": "heimdall"}},
		},
		"yaml encoded scalar": {
			ct:     "application/yaml; charset=utf-8",
			body:   "heimdall\n",
			expect: "heimdall",
		},
		"plain text": {
			ct:     "text/plain",
			body:   "content=heimdall",
			expect: "content=heimdall",
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			headers := make(http.Header)
			headers.Set("Content-Type", tc.ct)

			source := &testBodySource{body: []byte(tc.body)}
			ctx := newTestRequestContext(t, http.MethodPost, "https://foo.bar/test", headers, source)

			// WHEN
			data := ctx.Request().Body()

			// THEN
			assert.Equal(t, tc.expect, data)
			assert.Equal(t, 1, source.calls)
		})
	}
}

func TestRequestContextRawBody(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		body     string
		prepare  func(t *testing.T, ctx *RequestContext)
		expected string
	}{
		"No body": {
			expected: "",
		},
		"Body present": {
			body:     "content=heimdall",
			expected: "content=heimdall",
		},
		"Body was already requested": {
			body: "content=heimdall",
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
			body: "content=heimdall",
			prepare: func(t *testing.T, ctx *RequestContext) {
				t.Helper()

				_ = ctx.Body()
			},
			expected: "content=heimdall",
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			source := &testBodySource{body: []byte(tc.body)}
			ctx := newTestRequestContext(t, http.MethodPost, "https://foo.bar/test", nil, source)

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
			assert.Equal(t, 1, source.calls)
		})
	}
}

func TestRequestContextRawBodyError(t *testing.T) {
	t.Parallel()

	// GIVEN
	source := &testBodySource{err: assert.AnError}
	ctx := newTestRequestContext(t, http.MethodPost, "https://foo.bar/test", nil, source)

	// WHEN
	body, err := ctx.RawBody()

	// THEN
	require.ErrorIs(t, err, assert.AnError)
	assert.Nil(t, body)
	assert.Equal(t, 1, source.calls)
}

func TestRequestContextRequestURLCaptures(t *testing.T) {
	t.Parallel()

	// GIVEN
	ctx := newTestRequestContext(t, http.MethodHead, "https://foo.bar/test", nil, nil)
	ctx.Request().URL.Captures = map[string]string{"a": "b"}

	// WHEN
	captures := ctx.Request().URL.Captures

	// THEN
	require.Len(t, captures, 1)
	assert.Equal(t, "b", captures["a"])
}

func TestRequestContextReset(t *testing.T) {
	t.Parallel()

	// GIVEN
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json; charset=utf-8")
	source := &testBodySource{body: []byte(`{ "content": "heimdall" }`)}

	ctx := newTestRequestContext(t, http.MethodHead, "https://foo.bar/test", headers, source)
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
	require.Nil(t, ctx.inputHeaders)
	require.Nil(t, ctx.bodySource)
	require.Nil(t, ctx.savedBody)
	require.Nil(t, ctx.rawBody)
	require.NoError(t, ctx.err)
	require.Nil(t, ctx.ctx)
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
	require.NotNil(t, ctx.connectionSpecificHeaders)
	require.Empty(t, ctx.connectionSpecificHeaders)
}

func TestRequestContextSetParent(t *testing.T) {
	t.Parallel()

	// GIVEN
	ctx := newTestRequestContext(t, http.MethodHead, "https://foo.bar/test", nil, nil)
	orig := ctx.Context()
	newParent := context.Background()

	// WHEN
	ctx.SetParent(newParent)

	// THEN
	assert.NotEqual(t, orig, ctx.ctx)
	assert.Equal(t, newParent, ctx.ctx)
}
