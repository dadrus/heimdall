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

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/dadrus/heimdall/internal/pipeline"
)

func TestCommitterCommit(t *testing.T) {
	t.Parallel()

	cf := newContextFactory()

	findHeader := func(headers []*corev3.HeaderValueOption, name string) *corev3.HeaderValue {
		for _, header := range headers {
			if header.GetHeader().GetKey() == name {
				return header.GetHeader()
			}
		}

		return nil
	}

	for uc, tc := range map[string]struct {
		updateContext func(t *testing.T, ctx pipeline.ExecutionContext)
		assert        func(t *testing.T, err error, response *envoy_auth.CheckResponse)
	}{
		"successful with header mutations": {
			updateContext: func(t *testing.T, ctx pipeline.ExecutionContext) {
				t.Helper()

				ctx.PrepareUpstreamView(nil)

				upstreamRequest := ctx.UpstreamRequest()
				upstreamRequest.AddHeader("x-for-upstream-1", "some-value-1")
				upstreamRequest.AddHeader("x-for-upstream-2", "some-value-2")
				upstreamRequest.AddHeader("x-for-upstream-1", "some-value-3")
			},
			assert: func(t *testing.T, err error, response *envoy_auth.CheckResponse) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, response)
				assert.Equal(t, int32(codes.OK), response.GetStatus().GetCode())

				okResponse := response.GetOkResponse()
				require.NotNil(t, okResponse)
				require.Len(t, okResponse.GetHeaders(), 2)

				header := findHeader(okResponse.GetHeaders(), "X-For-Upstream-1")
				require.NotNil(t, header)
				assert.Equal(t, "some-value-1,some-value-3", header.GetValue())

				header = findHeader(okResponse.GetHeaders(), "X-For-Upstream-2")
				require.NotNil(t, header)
				assert.Equal(t, "some-value-2", header.GetValue())
			},
		},
		"explicit mutation is returned even if value equals incoming header": {
			updateContext: func(t *testing.T, ctx pipeline.ExecutionContext) {
				t.Helper()

				ctx.PrepareUpstreamView(nil)
				ctx.UpstreamRequest().SetHeader("X-Foo-Bar", "barfoo")
			},
			assert: func(t *testing.T, err error, response *envoy_auth.CheckResponse) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, response)

				okResponse := response.GetOkResponse()
				require.NotNil(t, okResponse)
				require.Len(t, okResponse.GetHeaders(), 1)

				header := findHeader(okResponse.GetHeaders(), "X-Foo-Bar")
				require.NotNil(t, header)
				assert.Equal(t, "barfoo", header.GetValue())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			httpReq := &envoy_auth.AttributeContext_HttpRequest{
				Method: http.MethodPatch,
				Scheme: "https",
				Host:   "foo.bar:8080",
				Path:   "/test",
				Headers: map[string]string{
					"x-foo-bar":                 "barfoo",
					"x-envoy-auth-partial-body": "false",
				},
			}
			checkReq := &envoy_auth.CheckRequest{
				Attributes: &envoy_auth.AttributeContext{
					Request: &envoy_auth.AttributeContext_Request{
						Http: httpReq,
					},
				},
			}
			ctr := newCommitter()
			ctx := cf.Create(requestInput{
				ctx: t.Context(),
				req: checkReq,
			})

			defer cf.Destroy(ctx)

			tc.updateContext(t, ctx)

			// WHEN
			resp, err := ctr.Commit(commitTarget{}, ctx)

			// THEN
			tc.assert(t, err, resp)
		})
	}
}
