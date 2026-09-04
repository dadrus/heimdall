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
	"context"
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

				require.ErrorIs(t, err, assert.AnError)
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
		"explicit header mutation is returned": {
			code: http.StatusMultiStatus,
			setup: func(t *testing.T, rc requestcontext.Context) {
				t.Helper()

				rc.PrepareUpstreamView(nil)
				rc.UpstreamRequest().AddHeader("X-Foo", "bar")
			},
			assert: func(t *testing.T, err error, rec *httptest.ResponseRecorder) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, []string{"bar"}, rec.Header().Values("X-Foo"))
				assert.Equal(t, http.StatusMultiStatus, rec.Code)
			},
		},
		"multiple values of explicit header mutation are returned": {
			code: http.StatusMultiStatus,
			setup: func(t *testing.T, rc requestcontext.Context) {
				t.Helper()

				rc.PrepareUpstreamView(nil)

				upstreamRequest := rc.UpstreamRequest()
				upstreamRequest.AddHeader("X-Foo", "bar")
				upstreamRequest.AddHeader("X-Foo", "foo")
			},
			assert: func(t *testing.T, err error, rec *httptest.ResponseRecorder) {
				t.Helper()

				require.NoError(t, err)
				assert.ElementsMatch(t, []string{"bar", "foo"}, rec.Header().Values("X-Foo"))
				assert.Equal(t, http.StatusMultiStatus, rec.Code)
			},
		},
		"unchanged request headers are not returned": {
			headers: http.Header{
				"X-Unchanged": []string{"foo"},
				"X-Replaced":  []string{"old"},
			},
			code: http.StatusOK,
			setup: func(t *testing.T, rc requestcontext.Context) {
				t.Helper()

				rc.PrepareUpstreamView(nil)

				upstreamRequest := rc.UpstreamRequest()
				upstreamRequest.SetHeader("X-Replaced", "new")
				upstreamRequest.SetHeader("X-New", "bar")
			},
			assert: func(t *testing.T, err error, rec *httptest.ResponseRecorder) {
				t.Helper()

				require.NoError(t, err)
				assert.Len(t, rec.Header(), 2)
				assert.Empty(t, rec.Header().Values("X-Unchanged"))
				assert.Equal(t, "new", rec.Header().Get("X-Replaced"))
				assert.Equal(t, "bar", rec.Header().Get("X-New"))
			},
		},
		"cookie mutation returns complete effective Cookie header": {
			headers: http.Header{
				"Cookie": []string{"existing=foo"},
			},
			code: http.StatusAccepted,
			setup: func(t *testing.T, rc requestcontext.Context) {
				t.Helper()

				rc.PrepareUpstreamView(nil)
				rc.UpstreamRequest().SetCookie("x-foo", "bar")
			},
			assert: func(t *testing.T, err error, rec *httptest.ResponseRecorder) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "existing=foo; x-foo=bar", rec.Header().Get("Cookie"))
				assert.Equal(t, http.StatusAccepted, rec.Code)
			},
		},
		"Host mutation is returned as regular header mutation": {
			code: http.StatusOK,
			setup: func(t *testing.T, rc requestcontext.Context) {
				t.Helper()

				rc.PrepareUpstreamView(nil)
				rc.UpstreamRequest().SetHeader("Host", "upstream.example")
			},
			assert: func(t *testing.T, err error, rec *httptest.ResponseRecorder) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "upstream.example", rec.Header().Get("Host"))
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			rw := httptest.NewRecorder()

			req, err := http.NewRequestWithContext(
				t.Context(),
				http.MethodPost,
				"http://heimdall.local/foo",
				nil,
			)
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
				reqCtx.PrepareUpstreamView(nil)
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

func TestRequestContextReset(t *testing.T) {
	t.Parallel()

	// GIVEN
	ctx := &requestContext{
		NetHTTPRequestContext: requestcontext.New(),
	}

	ctx.Init(
		httptest.NewRecorder(),
		httptest.NewRequestWithContext(
			t.Context(),
			http.MethodGet,
			"https://foo.bar/test",
			nil,
		),
		http.StatusOK,
	)
	ctx.PrepareUpstreamView(nil)

	ctx.UpstreamRequest().AddHeader("X-Foo", "bar")
	ctx.UpstreamRequest().SetCookie("x-foo", "bar")

	// WHEN
	ctx.Reset()

	// THEN
	assert.Nil(t, ctx.UpstreamRequest())
	assert.False(t, ctx.upstreamViewPrepared)
	assert.Nil(t, ctx.rw)
	assert.Zero(t, ctx.responseCode)
	assert.Empty(t, ctx.UpstreamHeaders())

	// AND
	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"https://bar.foo/new",
		nil,
	)
	req.Header.Set("X-New", "bar")

	ctx.Init(rw, req, http.StatusAccepted)
	ctx.PrepareUpstreamView(nil)

	assert.Equal(t, http.StatusAccepted, ctx.responseCode)
	assert.Same(t, rw, ctx.rw)
	assert.Equal(t, http.Header{
		"Host":  []string{"bar.foo"},
		"X-New": []string{"bar"},
	}, ctx.UpstreamRequest().Headers())
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
		http.StatusOK,
	)

	orig := ctx.Context()

	// WHEN
	actual := ctx.WithParent(t.Context())

	// THEN
	assert.Same(t, ctx, actual)
	assert.NotEqual(t, orig, ctx.Context())
	assert.Equal(t, t.Context(), ctx.Context())
}
