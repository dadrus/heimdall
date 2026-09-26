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
			req := httptest.NewRequestWithContext(
				t.Context(),
				http.MethodGet,
				"https://foo.bar/test",
				nil,
			)

			cf := newContextFactory()
			reqCtx := cf.Create(req)

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
		httptest.NewRequestWithContext(
			t.Context(),
			http.MethodGet,
			"https://foo.bar/test",
			nil,
		),
	)
	ctx.PrepareUpstreamView(nil)

	ctx.UpstreamRequest().AddHeader("X-Foo", "bar")
	ctx.UpstreamRequest().SetCookie("x-foo", "bar")

	// WHEN
	ctx.Reset()

	// THEN
	assert.Nil(t, ctx.UpstreamRequest())
	assert.False(t, ctx.upstreamViewPrepared)
	assert.Empty(t, ctx.UpstreamHeaders())

	// AND
	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"https://bar.foo/new",
		nil,
	)
	req.Header.Set("X-New", "bar")

	ctx.Init(req)
	ctx.PrepareUpstreamView(nil)

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
