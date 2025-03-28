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
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequestContextRequestClientIPs(t *testing.T) {
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
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			req := httptest.NewRequest(http.MethodHead, "https://foo.bar/test", nil)
			tc.configureRequest(t, req)

			ctx := &RequestContext{req: req}

			// WHEN
			ips := ctx.requestClientIPs()

			// THEN
			tc.assert(t, ips)
		})
	}
}

func TestRequestContextHeaders(t *testing.T) {
	t.Parallel()

	// GIVEN
	req := httptest.NewRequest(http.MethodHead, "https://foo.baz/test", nil)
	req.Header.Set("X-Foo-Bar", "foo")
	req.Header.Add("X-Foo-Bar", "bar")

	ctx := New(req)

	// WHEN
	headers := ctx.Request().Headers()

	// THEN
	require.Len(t, headers, 2)
	assert.Equal(t, "foo,bar", headers["X-Foo-Bar"])
	assert.Equal(t, "foo.baz", headers["Host"])
}

func TestRequestContextHeader(t *testing.T) {
	t.Parallel()

	// GIVEN
	req := httptest.NewRequest(http.MethodHead, "https://foo.bar/test", nil)
	req.Header.Set("X-Foo-Bar", "foo")
	req.Header.Add("X-Foo-Bar", "bar")
	req.Host = "bar.foo"

	ctx := New(req)

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
	req := httptest.NewRequest(http.MethodHead, "https://foo.bar/test", nil)
	req.Header.Set("Cookie", "foo=bar; bar=baz")

	ctx := New(req)

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
		"yaml encoded": {
			ct:     "application/yaml; charset=utf-8",
			body:   bytes.NewBufferString("content: heimdall"),
			expect: map[string]any{"content": "heimdall"},
		},
		"plain text": {
			ct:     "text/plain",
			body:   bytes.NewBufferString("content=heimdall"),
			expect: "content=heimdall",
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			req := httptest.NewRequest(http.MethodPost, "https://foo.bar/test", tc.body)
			req.Header.Set("Content-Type", tc.ct)

			ctx := New(req)

			// WHEN
			data := ctx.Request().Body()

			// THEN
			assert.Equal(t, tc.expect, data)
		})
	}
}
