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
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/pipeline"
)

type errorReader struct {
	err error
}

func (r errorReader) Read([]byte) (int, error) {
	return 0, r.err
}

func TestNetHTTPRequestContextInit(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		configureRequest func(req *http.Request)
		assert           func(t *testing.T, req *http.Request, ctx *NetHTTPRequestContext, err error)
	}{
		"valid request": {
			configureRequest: func(req *http.Request) {
				req.Header.Set("X-Foo", "bar")
				req.Header.Set("Connection", "X-Hop")
				req.Header.Set("X-Hop", "incoming")
				req.Host = "Bar.foo"
			},
			assert: func(t *testing.T, req *http.Request, ctx *NetHTTPRequestContext, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Same(t, req, ctx.req)
				assert.Equal(t, req.Context(), ctx.Context())
				assert.Equal(t, http.MethodPatch, ctx.Method())
				assert.Equal(t, "https", ctx.URL().Scheme)
				assert.Equal(t, "bar.foo", ctx.URL().Host)
				assert.Equal(t, "/test", ctx.URL().Path)
				assert.Equal(t, "foo=bar", ctx.URL().RawQuery)
				assert.Equal(t, "bar", ctx.Request().Header("X-Foo"))
				assert.Equal(t, "bar.foo", ctx.Request().Header("Host"))

				require.Len(t, ctx.Request().ClientIPAddresses, 1)
				assert.Equal(t, "192.0.2.1", ctx.Request().ClientIPAddresses[0])

				actual := make([]string, 0, 1)
				for name := range ctx.ConnectionSpecificHeaders() {
					actual = append(actual, name)
				}

				assert.ElementsMatch(t, []string{"X-Hop"}, actual)
			},
		},
		"invalid forwarded URI": {
			configureRequest: func(req *http.Request) {
				req.Header.Set("X-Forwarded-Uri", "/admin/%zz")
			},
			assert: func(t *testing.T, _ *http.Request, ctx *NetHTTPRequestContext, err error) {
				t.Helper()

				require.ErrorIs(t, err, ErrInvalidForwardedURI)
				assert.Nil(t, ctx.req)
				assert.Nil(t, ctx.Context())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			req := httptest.NewRequestWithContext(
				t.Context(),
				http.MethodPatch,
				"https://foo.bar/test?foo=bar",
				nil,
			)
			tc.configureRequest(req)

			ctx := New()

			// WHEN
			err := ctx.Init(req)

			// THEN
			tc.assert(t, req, ctx, err)
		})
	}
}

func TestNetHTTPRequestContextUpstreamRequest(t *testing.T) {
	t.Parallel()

	// GIVEN
	ctx := New()
	err := ctx.Init(httptest.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"https://foo.bar/test",
		nil,
	))
	require.NoError(t, err)

	// WHEN
	upstreamRequest := ctx.UpstreamRequest()

	// THEN
	assert.Nil(t, upstreamRequest)
}

func TestNetHTTPRequestContextRawBody(t *testing.T) {
	t.Parallel()

	expectedReadErr := errors.New("read failed")

	for uc, tc := range map[string]struct {
		setup  func(*http.Request)
		assert func(t *testing.T, req *http.Request, body io.ReadCloser, err error)
	}{
		"No body": {
			setup: func(req *http.Request) {},
			assert: func(t *testing.T, req *http.Request, body io.ReadCloser, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, body)

				data, err := io.ReadAll(body)
				require.NoError(t, err)
				require.NoError(t, body.Close())

				assert.Empty(t, data)
			},
		},
		"Body present": {
			setup: func(req *http.Request) {
				req.Body = io.NopCloser(bytes.NewBufferString("content=heimdall"))
			},
			assert: func(t *testing.T, req *http.Request, body io.ReadCloser, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, body)

				data, err := io.ReadAll(body)
				require.NoError(t, err)
				require.NoError(t, body.Close())

				assert.Equal(t, "content=heimdall", string(data))

				requestBody, err := io.ReadAll(req.Body)
				require.NoError(t, err)

				assert.Equal(t, "content=heimdall", string(requestBody))
			},
		},
		"Body exceeds configured limit": {
			setup: func(req *http.Request) {
				req.Body = http.MaxBytesReader(
					httptest.NewRecorder(),
					io.NopCloser(strings.NewReader("123456")),
					5,
				)
			},
			assert: func(t *testing.T, _ *http.Request, body io.ReadCloser, err error) {
				t.Helper()

				require.Nil(t, body)
				require.ErrorIs(t, err, pipeline.ErrRequestBodyTooLarge)

				var maxBytesErr *http.MaxBytesError

				require.ErrorAs(t, err, &maxBytesErr)
				assert.Equal(t, int64(5), maxBytesErr.Limit)
			},
		},
		"Body read fails": {
			setup: func(req *http.Request) {
				req.Body = io.NopCloser(errorReader{err: expectedReadErr})
			},
			assert: func(t *testing.T, _ *http.Request, body io.ReadCloser, err error) {
				t.Helper()

				require.Nil(t, body)
				require.ErrorIs(t, err, expectedReadErr)
				require.NotErrorIs(t, err, pipeline.ErrRequestBodyTooLarge)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			// GIVEN
			req := httptest.NewRequestWithContext(
				t.Context(),
				http.MethodPost,
				"https://foo.bar/test",
				nil,
			)
			tc.setup(req)

			ctx := New()
			err := ctx.Init(req)
			require.NoError(t, err)

			// WHEN
			body, err := ctx.RawBody()

			// THEN
			tc.assert(t, req, body, err)
		})
	}
}

func TestNetHTTPRequestContextReset(t *testing.T) {
	t.Parallel()

	// GIVEN
	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"https://foo.bar/test",
		bytes.NewBufferString("content=heimdall"),
	)

	ctx := New()
	err := ctx.Init(req)
	require.NoError(t, err)
	_, err = ctx.RawBody()
	require.NoError(t, err)

	// WHEN
	ctx.Reset()

	// THEN
	assert.Nil(t, ctx.req)
	assert.Nil(t, ctx.bodySource.req)
	assert.Nil(t, ctx.RequestContext.inputHeaders)
	assert.Nil(t, ctx.RequestContext.bodySource)
}
