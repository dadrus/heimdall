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

package decision

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/handler/requestcontext"
)

func TestRequestContextFinalize(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		headers http.Header
		code    int
		setup   func(t *testing.T, rc requestcontext.Context)
		assert  func(t *testing.T, err error, rec *httptest.ResponseRecorder)
	}{
		"finalize returns error": {
			setup: func(t *testing.T, rc requestcontext.Context) {
				t.Helper()

				rc.SetError(assert.AnError)
			},
			assert: func(t *testing.T, err error, _ *httptest.ResponseRecorder) {
				t.Helper()

				require.Error(t, err)
			},
		},
		"only response code is set": {
			code: http.StatusNoContent,
			setup: func(t *testing.T, _ requestcontext.Context) {
				t.Helper()
			},
			assert: func(t *testing.T, err error, rec *httptest.ResponseRecorder) {
				t.Helper()

				require.NoError(t, err)

				assert.Empty(t, rec.Header())
				assert.Equal(t, http.StatusNoContent, rec.Code)
			},
		},
		"response code and single header are set": {
			code: http.StatusMultiStatus,
			setup: func(t *testing.T, rc requestcontext.Context) {
				t.Helper()

				rc.AddHeaderForUpstream("X-Foo", "bar")
			},
			assert: func(t *testing.T, err error, rec *httptest.ResponseRecorder) {
				t.Helper()

				require.NoError(t, err)

				assert.Len(t, rec.Header(), 1)
				assert.Equal(t, "bar", rec.Header().Get("X-Foo"))
				assert.Equal(t, http.StatusMultiStatus, rec.Code)
			},
		},
		"response code and multiple header with same name but different values are set": {
			code: http.StatusMultiStatus,
			setup: func(t *testing.T, rc requestcontext.Context) {
				t.Helper()

				rc.AddHeaderForUpstream("X-Foo", "bar")
				rc.AddHeaderForUpstream("X-Foo", "foo")
			},
			assert: func(t *testing.T, err error, rec *httptest.ResponseRecorder) {
				t.Helper()

				require.NoError(t, err)

				assert.Len(t, rec.Header(), 1)
				values := rec.Header().Values("X-Foo")
				assert.Len(t, values, 2)
				assert.ElementsMatch(t, values, []string{"bar", "foo"})

				assert.Equal(t, http.StatusMultiStatus, rec.Code)
			},
		},
		"response code and single cookie are set": {
			code: http.StatusAccepted,
			setup: func(t *testing.T, rc requestcontext.Context) {
				t.Helper()

				rc.AddCookieForUpstream("x-foo", "bar")
			},
			assert: func(t *testing.T, err error, rec *httptest.ResponseRecorder) {
				t.Helper()

				require.NoError(t, err)

				assert.Len(t, rec.Header(), 1)
				assert.Equal(t, "x-foo=bar", rec.Header().Get("Cookie"))
				assert.Equal(t, http.StatusAccepted, rec.Code)
			},
		},
		"multiple headers and cookies are set": {
			code: http.StatusOK,
			setup: func(t *testing.T, rc requestcontext.Context) {
				t.Helper()

				rc.AddHeaderForUpstream("X-Foo", "bar")
				rc.AddHeaderForUpstream("X-Bar", "foo")
				rc.AddHeaderForUpstream("X-Bar", "bar")
				rc.AddCookieForUpstream("x-foo", "bar")
				rc.AddCookieForUpstream("x-bar", "foo")
			},
			assert: func(t *testing.T, err error, rec *httptest.ResponseRecorder) {
				t.Helper()

				require.NoError(t, err)

				assert.Len(t, rec.Header(), 3)

				cookies, err := http.ParseCookie(rec.Header().Get("Cookie"))
				require.NoError(t, err)
				require.Len(t, cookies, 2)

				cookieValues := make(map[string]string, len(cookies))
				for _, cookie := range cookies {
					cookieValues[cookie.Name] = cookie.Value
				}

				assert.Equal(t, map[string]string{
					"x-foo": "bar",
					"x-bar": "foo",
				}, cookieValues)

				assert.ElementsMatch(t, rec.Header().Values("X-Foo"), []string{"bar"})
				assert.ElementsMatch(t, rec.Header().Values("X-Bar"), []string{"bar", "foo"})
				assert.Equal(t, http.StatusOK, rec.Code)
			},
		},
		"only changed replaced headers are set": {
			code: http.StatusOK,
			headers: http.Header{
				"X-Unchanged": []string{"foo"},
				"X-Replaced":  []string{"old"},
			},
			setup: func(t *testing.T, rc requestcontext.Context) {
				t.Helper()

				rc.PrepareUpstreamRequest(nil)

				headers := rc.UpstreamRequest().HeaderSnapshot()
				headers.Set("X-Replaced", "new")
				headers.Set("X-New", "bar")

				rc.UpstreamRequest().ReplaceHeaders(headers)
			},
			assert: func(t *testing.T, err error, rec *httptest.ResponseRecorder) {
				t.Helper()

				require.NoError(t, err)

				assert.Len(t, rec.Header(), 2)
				assert.Empty(t, rec.Header().Values("X-Unchanged"))
				assert.Equal(t, "new", rec.Header().Get("X-Replaced"))
				assert.Equal(t, "bar", rec.Header().Get("X-New"))
				assert.Equal(t, http.StatusOK, rec.Code)
			},
		},
		"cookie header and cookie are combined": {
			code: http.StatusOK,
			setup: func(t *testing.T, rc requestcontext.Context) {
				t.Helper()

				rc.AddHeaderForUpstream("Cookie", "x-foo=bar")
				rc.AddCookieForUpstream("x-bar", "foo")
			},
			assert: func(t *testing.T, err error, rec *httptest.ResponseRecorder) {
				t.Helper()

				require.NoError(t, err)

				assert.Len(t, rec.Header(), 1)

				values := rec.Header().Values("Cookie")
				require.Len(t, values, 1)

				cookies, err := http.ParseCookie(values[0])
				require.NoError(t, err)
				require.Len(t, cookies, 2)

				cookieValues := make(map[string]string, len(cookies))
				for _, cookie := range cookies {
					cookieValues[cookie.Name] = cookie.Value
				}

				assert.Equal(t, map[string]string{
					"x-foo": "bar",
					"x-bar": "foo",
				}, cookieValues)

				assert.Equal(t, http.StatusOK, rec.Code)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			rw := httptest.NewRecorder()

			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://heimdall.local/foo", nil)
			require.NoError(t, err)

			if tc.headers != nil {
				req.Header = tc.headers.Clone()
			}

			cf := newContextFactory(tc.code)
			reqCtx := cf.Create(rw, req)

			defer cf.Destroy(reqCtx)

			tc.setup(t, reqCtx)

			// WHEN
			err = reqCtx.Finalize()

			// THEN
			tc.assert(t, err, rw)
		})
	}
}

func TestRequestContextUpstreamRequest(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		prepared bool
	}{
		"upstream request is not available before preparation": {},
		"upstream request is available after preparation": {
			prepared: true,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			rw := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(
				t.Context(),
				http.MethodGet,
				"https://foo.bar/test",
				nil,
			)

			cf := newContextFactory(http.StatusOK)
			reqCtx := cf.Create(rw, req)

			defer cf.Destroy(reqCtx)

			if tc.prepared {
				reqCtx.PrepareUpstreamRequest(nil)
			}

			// WHEN
			upstreamRequest := reqCtx.UpstreamRequest()

			// THEN
			if tc.prepared {
				require.NotNil(t, upstreamRequest)
				assert.Same(t, reqCtx, upstreamRequest)
			} else {
				assert.Nil(t, upstreamRequest)
			}
		})
	}
}

func TestRequestContextMethod(t *testing.T) {
	t.Parallel()

	// GIVEN
	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPatch,
		"https://foo.bar/test",
		nil,
	)

	cf := newContextFactory(http.StatusOK)
	reqCtx := cf.Create(rw, req)

	defer cf.Destroy(reqCtx)

	reqCtx.PrepareUpstreamRequest(nil)

	// WHEN
	method := reqCtx.UpstreamRequest().Method()

	// THEN
	assert.Equal(t, http.MethodPatch, method)
}

func TestRequestContextAuthority(t *testing.T) {
	t.Parallel()

	// GIVEN
	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"https://foo.bar/test",
		nil,
	)

	cf := newContextFactory(http.StatusOK)
	reqCtx := cf.Create(rw, req)

	defer cf.Destroy(reqCtx)

	reqCtx.PrepareUpstreamRequest(nil)

	// WHEN
	authority := reqCtx.UpstreamRequest().Authority()

	// THEN
	assert.Equal(t, "foo.bar", authority)
}

func TestRequestContextURL(t *testing.T) {
	t.Parallel()

	// GIVEN
	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"https://foo.bar/test?foo=bar",
		nil,
	)

	cf := newContextFactory(http.StatusOK)
	reqCtx := cf.Create(rw, req)

	defer cf.Destroy(reqCtx)

	reqCtx.PrepareUpstreamRequest(nil)
	upstreamRequest := reqCtx.UpstreamRequest()

	// WHEN
	upstreamURL := upstreamRequest.URL()

	// THEN
	assert.Equal(t, "https", upstreamURL.Scheme)
	assert.Equal(t, "foo.bar", upstreamURL.Host)
	assert.Equal(t, "/test", upstreamURL.Path)
	assert.Equal(t, "foo=bar", upstreamURL.RawQuery)

	upstreamURL.Host = "bar.foo"
	upstreamURL.Path = "/changed"

	assert.Equal(t, "foo.bar", upstreamRequest.URL().Host)
	assert.Equal(t, "/test", upstreamRequest.URL().Path)
}

func TestRequestContextAddHeader(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		name                   string
		values                 []string
		expectedSnapshotValues []string
		expectedResponseValues []string
	}{
		"header is added": {
			name:                   "X-Foo",
			values:                 []string{"bar"},
			expectedSnapshotValues: []string{"bar"},
		},
		"multiple header values are added": {
			name:                   "X-Foo",
			values:                 []string{"bar", "foo"},
			expectedSnapshotValues: []string{"bar", "foo"},
		},
		"Host is treated as regular decision response header": {
			name:                   "Host",
			values:                 []string{"bar.foo"},
			expectedSnapshotValues: []string{},
			expectedResponseValues: []string{"bar.foo"},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			rw := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(
				t.Context(),
				http.MethodGet,
				"https://foo.bar/test",
				nil,
			)

			cf := newContextFactory(http.StatusOK)
			reqCtx := cf.Create(rw, req)

			defer cf.Destroy(reqCtx)

			reqCtx.PrepareUpstreamRequest(nil)
			upstreamRequest := reqCtx.UpstreamRequest()

			// WHEN
			for _, value := range tc.values {
				upstreamRequest.AddHeader(tc.name, value)
			}

			// THEN
			assert.ElementsMatch(
				t,
				tc.expectedSnapshotValues,
				upstreamRequest.HeaderSnapshot().Values(tc.name),
			)
			assert.Equal(t, "foo.bar", upstreamRequest.Authority())

			if tc.expectedResponseValues != nil {
				require.NoError(t, reqCtx.Finalize())
				assert.ElementsMatch(t, tc.expectedResponseValues, rw.Header().Values(tc.name))
			}
		})
	}
}

func TestRequestContextSetCookie(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		values   []string
		expected map[string]string
	}{
		"cookie is added": {
			values: []string{"bar"},
			expected: map[string]string{
				"existing": "foo",
				"x-foo":    "bar",
			},
		},
		"last value wins": {
			values: []string{"bar", "baz"},
			expected: map[string]string{
				"existing": "foo",
				"x-foo":    "baz",
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			rw := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(
				t.Context(),
				http.MethodGet,
				"https://foo.bar/test",
				nil,
			)
			req.Header.Set("Cookie", "existing=foo")

			cf := newContextFactory(http.StatusOK)
			reqCtx := cf.Create(rw, req)

			defer cf.Destroy(reqCtx)

			reqCtx.PrepareUpstreamRequest(nil)
			upstreamRequest := reqCtx.UpstreamRequest()

			// WHEN
			for _, value := range tc.values {
				upstreamRequest.SetCookie("x-foo", value)
			}

			// THEN
			cookies, err := http.ParseCookie(upstreamRequest.HeaderSnapshot().Get("Cookie"))
			require.NoError(t, err)

			cookieValues := make(map[string]string, len(cookies))
			for _, cookie := range cookies {
				cookieValues[cookie.Name] = cookie.Value
			}

			assert.Equal(t, tc.expected, cookieValues)
		})
	}
}

func TestRequestContextHeaderSnapshot(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		requestHeaders  http.Header
		upstreamHeaders http.Header
		upstreamCookies map[string]string
		expected        http.Header
		detached        bool
	}{
		"request headers are returned without Host": {
			requestHeaders: http.Header{
				"Host":  []string{"bar.foo"},
				"X-Foo": []string{"bar"},
			},
			expected: http.Header{
				"X-Foo": []string{"bar"},
			},
			detached: true,
		},
		"upstream mutations are applied": {
			requestHeaders: http.Header{
				"Cookie": []string{"existing=foo"},
				"X-Foo":  []string{"original"},
				"X-Bar":  []string{"bar"},
			},
			upstreamHeaders: http.Header{
				"X-Foo": []string{"from-heimdall-1", "from-heimdall-2"},
			},
			upstreamCookies: map[string]string{
				"x-foo": "bar",
			},
			expected: http.Header{
				"Cookie": []string{"existing=foo; x-foo=bar"},
				"X-Foo":  []string{"from-heimdall-1", "from-heimdall-2"},
				"X-Bar":  []string{"bar"},
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			rw := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(
				t.Context(),
				http.MethodGet,
				"https://foo.bar/test",
				nil,
			)
			req.Header = tc.requestHeaders.Clone()

			cf := newContextFactory(http.StatusOK)
			reqCtx := cf.Create(rw, req)

			defer cf.Destroy(reqCtx)

			reqCtx.PrepareUpstreamRequest(nil)
			upstreamRequest := reqCtx.UpstreamRequest()

			for name, values := range tc.upstreamHeaders {
				for _, value := range values {
					upstreamRequest.AddHeader(name, value)
				}
			}

			for name, value := range tc.upstreamCookies {
				upstreamRequest.SetCookie(name, value)
			}

			// WHEN
			headers := upstreamRequest.HeaderSnapshot()

			// THEN
			assert.Equal(t, tc.expected, headers)

			if tc.detached {
				headers.Set("X-Foo", "changed")

				assert.Equal(t, tc.expected, upstreamRequest.HeaderSnapshot())
			}
		})
	}
}

func TestRequestContextReplaceHeaders(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		replacement       http.Header
		headersAfter      http.Header
		cookiesAfter      map[string]string
		mutateReplacement bool
		expected          http.Header
	}{
		"headers are replaced and previous mutations are cleared": {
			replacement: http.Header{
				"Host":       []string{"bar.foo"},
				"X-Replaced": []string{"foo"},
			},
			expected: http.Header{
				"X-Replaced": []string{"foo"},
			},
		},
		"nil replaces headers with empty state": {
			expected: http.Header{},
		},
		"mutations after replacement are applied": {
			replacement: http.Header{
				"X-Replaced": []string{"foo"},
			},
			headersAfter: http.Header{
				"X-After": []string{"bar"},
			},
			cookiesAfter: map[string]string{
				"x-foo": "bar",
			},
			expected: http.Header{
				"Cookie":     []string{"x-foo=bar"},
				"X-After":    []string{"bar"},
				"X-Replaced": []string{"foo"},
			},
		},
		"ownership of replacement headers is transferred": {
			replacement: http.Header{
				"X-Replaced": []string{"foo"},
			},
			mutateReplacement: true,
			expected: http.Header{
				"X-Replaced": []string{"bar"},
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			rw := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(
				t.Context(),
				http.MethodGet,
				"https://foo.bar/test",
				nil,
			)
			req.Header.Set("X-Original", "foo")

			cf := newContextFactory(http.StatusOK)
			reqCtx := cf.Create(rw, req)

			defer cf.Destroy(reqCtx)

			reqCtx.PrepareUpstreamRequest(nil)
			upstreamRequest := reqCtx.UpstreamRequest()

			upstreamRequest.AddHeader("X-Before", "foo")
			upstreamRequest.SetCookie("before", "foo")

			replacement := tc.replacement.Clone()

			// WHEN
			upstreamRequest.ReplaceHeaders(replacement)

			if tc.mutateReplacement {
				replacement.Set("X-Replaced", "bar")
			}

			for name, values := range tc.headersAfter {
				for _, value := range values {
					upstreamRequest.AddHeader(name, value)
				}
			}

			for name, value := range tc.cookiesAfter {
				upstreamRequest.SetCookie(name, value)
			}

			// THEN
			assert.Equal(t, tc.expected, upstreamRequest.HeaderSnapshot())
		})
	}
}

func TestRequestContextReset(t *testing.T) {
	t.Parallel()

	// GIVEN
	ctx := &requestContext{
		RequestContext: requestcontext.New(),
	}

	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"https://foo.bar/test",
		nil,
	)

	ctx.Init(rw, req, http.StatusOK)
	ctx.PrepareUpstreamRequest(nil)

	upstreamRequest := ctx.UpstreamRequest()
	upstreamRequest.AddHeader("X-Foo", "bar")
	upstreamRequest.SetCookie("x-foo", "bar")
	upstreamRequest.ReplaceHeaders(http.Header{
		"X-Replaced": []string{"foo"},
	})

	// WHEN
	ctx.Reset()

	// THEN
	assert.Nil(t, ctx.UpstreamRequest())

	newReq := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"https://bar.foo/new",
		nil,
	)
	newReq.Header.Set("X-New", "bar")

	ctx.Init(httptest.NewRecorder(), newReq, http.StatusAccepted)
	ctx.PrepareUpstreamRequest(nil)

	assert.Equal(t, http.Header{
		"X-New": []string{"bar"},
	}, ctx.UpstreamRequest().HeaderSnapshot())
}
