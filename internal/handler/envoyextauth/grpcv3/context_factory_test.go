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

package grpcv3

import (
	"net/http"
	"testing"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContextFactoryCreate(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		req    *envoy_auth.CheckRequest
		assert func(t *testing.T, rctx *RequestContext, err error)
	}{
		"successful": {
			req: &envoy_auth.CheckRequest{
				Attributes: &envoy_auth.AttributeContext{
					Request: &envoy_auth.AttributeContext_Request{
						Http: &envoy_auth.AttributeContext_HttpRequest{
							Method: http.MethodGet,
							Path:   "/foo",
						},
					},
				},
			},
			assert: func(t *testing.T, rctx *RequestContext, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, rctx.Context())
			},
		},
		"erroneous": {
			req: &envoy_auth.CheckRequest{
				Attributes: &envoy_auth.AttributeContext{
					Request: &envoy_auth.AttributeContext_Request{
						Http: &envoy_auth.AttributeContext_HttpRequest{
							Method: http.MethodGet,
							Path:   "/foo/%zz",
						},
					},
				},
			},
			assert: func(t *testing.T, rctx *RequestContext, err error) {
				t.Helper()

				require.ErrorIs(t, err, errInvalidRequestURI)
				// context is resetted on errors
				assert.Nil(t, rctx.Context())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			seed := newRequestContext()
			cf := newContextFactory()
			cf.pool.New = func() any { return seed }

			ctx, err := cf.Create(requestInput{ctx: t.Context(), req: tc.req})
			if err == nil {
				defer cf.Destroy(ctx)
			}

			tc.assert(t, seed, err)
		})
	}
}
