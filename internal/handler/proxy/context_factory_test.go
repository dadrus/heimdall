// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/handler/requestcontext"
)

func TestContextFactoryCreate(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		req    *http.Request
		assert func(t *testing.T, rctx *requestContext, err error)
	}{
		"successful": {
			req: httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/foo", nil),
			assert: func(t *testing.T, rctx *requestContext, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, rctx.Context())
			},
		},
		"erroneous": {
			req: func() *http.Request {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/foo", nil)
				req.Header.Set("X-Forwarded-Uri", "/foo/%zz")

				return req
			}(),
			assert: func(t *testing.T, rctx *requestContext, err error) {
				t.Helper()

				require.ErrorIs(t, err, requestcontext.ErrInvalidForwardedURI)
				// Context state is reset on initialization errors.
				assert.Nil(t, rctx.Context())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			// GIVEN
			seed := &requestContext{NetHTTPRequestContext: requestcontext.New()}
			seed.SetParent(t.Context())

			cf := newContextFactory()
			cf.pool.New = func() any { return seed }

			// WHEN
			ctx, err := cf.Create(tc.req)
			if err == nil {
				defer cf.Destroy(ctx)
			}

			// THEN
			tc.assert(t, seed, err)
		})
	}
}
