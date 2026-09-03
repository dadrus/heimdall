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

func TestNetHTTPRequestContextInit(t *testing.T) {
	t.Parallel()

	// GIVEN
	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPatch,
		"https://foo.bar/test?foo=bar",
		nil,
	)
	req.Header.Set("X-Foo", "bar")
	req.Header.Set("Connection", "X-Hop")
	req.Header.Set("X-Hop", "incoming")
	req.Host = "Bar.foo"

	ctx := New()

	// WHEN
	ctx.Init(req)

	// THEN
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
}

func TestNetHTTPRequestContextUpstreamRequest(t *testing.T) {
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

func TestNetHTTPRequestContextRawBodyRestoresRequestBody(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		body     io.Reader
		expected string
	}{
		"No body": {
			expected: "",
		},
		"Body present": {
			body:     bytes.NewBufferString("content=heimdall"),
			expected: "content=heimdall",
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			req := httptest.NewRequestWithContext(
				t.Context(),
				http.MethodPost,
				"https://foo.bar/test",
				tc.body,
			)

			ctx := New()
			ctx.Init(req)

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
	ctx.Init(req)
	_, err := ctx.RawBody()
	require.NoError(t, err)

	// WHEN
	ctx.Reset()

	// THEN
	assert.Nil(t, ctx.req)
	assert.Nil(t, ctx.bodySource.req)
	assert.Nil(t, ctx.RequestContext.inputHeaders)
	assert.Nil(t, ctx.RequestContext.bodySource)
}
