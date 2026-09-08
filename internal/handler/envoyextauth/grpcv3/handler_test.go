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

package grpcv3

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/pipeline"
	mocks3 "github.com/dadrus/heimdall/internal/pipeline/mocks"
)

func TestHandleDecisionEndpointRequest(t *testing.T) {
	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, cfg *config.Configuration, req *envoy_auth.CheckRequest, exec *mocks3.ExecutorMock)
		assert func(t *testing.T, err error, response *envoy_auth.CheckResponse)
	}{
		"no rules configured": {
			setup: func(t *testing.T, _ *config.Configuration, _ *envoy_auth.CheckRequest, exec *mocks3.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(mock.Anything).Return(pipeline.ErrNoRuleFound)
			},
			assert: func(t *testing.T, err error, response *envoy_auth.CheckResponse) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, int32(codes.NotFound), response.GetStatus().GetCode())

				deniedResponse := response.GetDeniedResponse()
				require.NotNil(t, deniedResponse)
				assert.Equal(t, typev3.StatusCode(http.StatusNotFound), deniedResponse.GetStatus().GetCode())
				assert.Empty(t, deniedResponse.GetBody())
				assert.Empty(t, deniedResponse.GetHeaders())
			},
		},
		"rule doesn't match method": {
			setup: func(t *testing.T, _ *config.Configuration, _ *envoy_auth.CheckRequest, exec *mocks3.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(mock.Anything).Return(pipeline.ErrNoRuleFound)
			},
			assert: func(t *testing.T, err error, response *envoy_auth.CheckResponse) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, int32(codes.NotFound), response.GetStatus().GetCode())

				deniedResponse := response.GetDeniedResponse()
				require.NotNil(t, deniedResponse)
				assert.Equal(t, typev3.StatusCode(http.StatusNotFound), deniedResponse.GetStatus().GetCode())
				assert.Empty(t, deniedResponse.GetBody())
				assert.Empty(t, deniedResponse.GetHeaders())
			},
		},
		"rule execution fails with authentication error": {
			setup: func(t *testing.T, _ *config.Configuration, _ *envoy_auth.CheckRequest, exec *mocks3.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(mock.Anything).Return(pipeline.ErrAuthentication)
			},
			assert: func(t *testing.T, err error, response *envoy_auth.CheckResponse) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, int32(codes.Unauthenticated), response.GetStatus().GetCode())

				deniedResponse := response.GetDeniedResponse()
				require.NotNil(t, deniedResponse)
				assert.Equal(t, typev3.StatusCode(http.StatusUnauthorized), deniedResponse.GetStatus().GetCode())
				assert.Empty(t, deniedResponse.GetBody())
				assert.Empty(t, deniedResponse.GetHeaders())
			},
		},
		"rule execution fails with authorization error": {
			setup: func(t *testing.T, _ *config.Configuration, _ *envoy_auth.CheckRequest, exec *mocks3.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(mock.Anything).Return(pipeline.ErrAuthorization)
			},
			assert: func(t *testing.T, err error, response *envoy_auth.CheckResponse) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, int32(codes.PermissionDenied), response.GetStatus().GetCode())

				deniedResponse := response.GetDeniedResponse()
				require.NotNil(t, deniedResponse)
				assert.Equal(t, typev3.StatusCode(http.StatusForbidden), deniedResponse.GetStatus().GetCode())
				assert.Empty(t, deniedResponse.GetBody())
				assert.Empty(t, deniedResponse.GetHeaders())
			},
		},
		"rule execution fails with a redirect": {
			setup: func(t *testing.T, _ *config.Configuration, _ *envoy_auth.CheckRequest, exec *mocks3.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(mock.Anything).Return(&pipeline.RedirectError{
					Code:       http.StatusFound,
					RedirectTo: "http://foo.bar",
				})
			},
			assert: func(t *testing.T, err error, response *envoy_auth.CheckResponse) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, int32(codes.FailedPrecondition), response.GetStatus().GetCode())

				deniedResponse := response.GetDeniedResponse()
				require.NotNil(t, deniedResponse)
				assert.Equal(t, typev3.StatusCode(http.StatusFound), deniedResponse.GetStatus().GetCode())
				assert.Empty(t, deniedResponse.GetBody())
				require.Len(t, deniedResponse.GetHeaders(), 1)
				assert.Equal(t, "Location", deniedResponse.GetHeaders()[0].GetHeader().GetKey())
				assert.Equal(t, "http://foo.bar", deniedResponse.GetHeaders()[0].GetHeader().GetValue())
			},
		},
		"rule execution succeeds": {
			setup: func(t *testing.T, _ *config.Configuration, _ *envoy_auth.CheckRequest, exec *mocks3.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(
					mock.MatchedBy(func(ctx pipeline.Context) bool {
						req := ctx.Request()

						return req.URL.Path == "/test" &&
							req.Method == http.MethodPost
					}),
				).Return(nil)
			},
			assert: func(t *testing.T, err error, response *envoy_auth.CheckResponse) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, int32(codes.OK), response.GetStatus().GetCode())

				okResponse := response.GetOkResponse()
				require.NotNil(t, okResponse)
				assert.Empty(t, okResponse.GetHeaders())
			},
		},
		"server panics and error does not contain traces": {
			setup: func(t *testing.T, _ *config.Configuration, _ *envoy_auth.CheckRequest, exec *mocks3.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(mock.Anything).Panic("wuff")
			},
			assert: func(t *testing.T, err error, _ *envoy_auth.CheckResponse) {
				t.Helper()

				require.Error(t, err)
				assert.Equal(t, "rpc error: code = Internal desc = internal error", err.Error())
			},
		},
		"invalid host is rejected": {
			setup: func(t *testing.T, _ *config.Configuration, req *envoy_auth.CheckRequest, _ *mocks3.ExecutorMock) {
				t.Helper()

				req.Attributes.Request.Http.Host = "evil.com,for=127.0.0.1"
			},
			assert: func(t *testing.T, err error, response *envoy_auth.CheckResponse) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, int32(codes.OK), response.GetStatus().GetCode())

				deniedResponse := response.GetDeniedResponse()
				require.NotNil(t, deniedResponse)
				assert.Equal(
					t,
					typev3.StatusCode_BadRequest,
					deniedResponse.GetStatus().GetCode(),
				)
				assert.Empty(t, deniedResponse.GetBody())
				assert.Empty(t, deniedResponse.GetHeaders())
			},
		},
		"request exceeds configured body limit": {
			setup: func(t *testing.T, conf *config.Configuration, req *envoy_auth.CheckRequest, _ *mocks3.ExecutorMock) {
				t.Helper()

				conf.Serve.Requests.Body.MaxSize = 1024
				req.Attributes.Request.Http.Body = strings.Repeat("x", 2*1024)
			},
			assert: func(t *testing.T, err error, response *envoy_auth.CheckResponse) {
				t.Helper()

				require.Error(t, err)
				assert.Equal(t, codes.ResourceExhausted, status.Code(err))
				assert.Nil(t, response)
			},
		},
		"disabled body limit allows request exceeding grpc default": {
			setup: func(t *testing.T, conf *config.Configuration, req *envoy_auth.CheckRequest, exec *mocks3.ExecutorMock) {
				t.Helper()

				conf.Serve.Requests.Body.MaxSize = 0
				req.Attributes.Request.Http.Body = strings.Repeat("x", 5*1024*1024)

				exec.EXPECT().Execute(mock.Anything).Return(nil)
			},
			assert: func(t *testing.T, err error, response *envoy_auth.CheckResponse) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, response)
				assert.Equal(t, int32(codes.OK), response.GetStatus().GetCode())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			lis := bufconn.Listen(8 * 1024 * 1024)
			conn, err := grpc.NewClient("passthrough://bufnet",
				grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
				grpc.WithTransportCredentials(insecure.NewCredentials()))
			require.NoError(t, err)

			conf := &config.Configuration{
				Metrics: config.MetricsConfig{
					Enabled: true,
				},
				Serve: config.ServeConfig{
					Requests: config.IngressRequests{
						Headers: config.IngressRequestHeaders{
							MaxSize: 64 * 1024,
						},
					},
				},
			}
			req := &envoy_auth.CheckRequest{
				Attributes: &envoy_auth.AttributeContext{
					Request: &envoy_auth.AttributeContext_Request{
						Http: &envoy_auth.AttributeContext_HttpRequest{
							Body:   "foo",
							Method: http.MethodPost,
							Path:   "/test",
							Host:   "heimdall.local",
						},
					},
				},
			}
			cch := mocks.NewCacheMock(t)
			exec := mocks3.NewExecutorMock(t)

			tc.setup(t, conf, req, exec)

			srv := newService(conf, cch, log.Logger, exec)

			defer srv.Stop()

			go func() {
				srv.Serve(lis)
			}()

			client := envoy_auth.NewAuthorizationClient(conn)

			// WHEN
			resp, err := client.Check(t.Context(), req)

			// THEN
			tc.assert(t, err, resp)
		})
	}
}
