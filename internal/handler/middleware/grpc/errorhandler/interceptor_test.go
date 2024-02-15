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

package errorhandler

import (
	"context"
	"net"
	"net/http"
	"testing"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/dadrus/heimdall/internal/handler/middleware/grpc/mocks"
	"github.com/dadrus/heimdall/internal/heimdall"
)

func TestErrorInterceptor(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc          string
		interceptor grpc.UnaryServerInterceptor
		err         error
		expGRPCCode codes.Code
		expHTTPCode envoy_type.StatusCode
		expBody     string
	}{
		{
			uc:          "no error",
			interceptor: New(),
			expGRPCCode: codes.OK,
			expHTTPCode: http.StatusOK,
		},
		{
			uc:          "authentication error default",
			interceptor: New(),
			err:         heimdall.ErrAuthentication,
			expGRPCCode: codes.Unauthenticated,
			expHTTPCode: http.StatusUnauthorized,
		},
		{
			uc:          "authentication error overridden",
			interceptor: New(WithAuthenticationErrorCode(http.StatusContinue)),
			err:         heimdall.ErrAuthentication,
			expGRPCCode: codes.Unauthenticated,
			expHTTPCode: http.StatusContinue,
		},
		{
			uc:          "authentication error verbose",
			interceptor: New(WithVerboseErrors(true)),
			err:         heimdall.ErrAuthentication,
			expGRPCCode: codes.Unauthenticated,
			expHTTPCode: http.StatusUnauthorized,
			expBody:     "<p>authentication error</p>",
		},
		{
			uc:          "authorization error default",
			interceptor: New(),
			err:         heimdall.ErrAuthorization,
			expGRPCCode: codes.PermissionDenied,
			expHTTPCode: http.StatusForbidden,
		},
		{
			uc:          "authorization error overridden",
			interceptor: New(WithAuthorizationErrorCode(http.StatusContinue)),
			err:         heimdall.ErrAuthorization,
			expGRPCCode: codes.PermissionDenied,
			expHTTPCode: http.StatusContinue,
		},
		{
			uc:          "authorization error verbose",
			interceptor: New(WithVerboseErrors(true)),
			err:         heimdall.ErrAuthorization,
			expGRPCCode: codes.PermissionDenied,
			expHTTPCode: http.StatusForbidden,
			expBody:     "<p>authorization error</p>",
		},
		{
			uc:          "communication timeout error default",
			interceptor: New(),
			err:         heimdall.ErrCommunicationTimeout,
			expGRPCCode: codes.DeadlineExceeded,
			expHTTPCode: http.StatusBadGateway,
		},
		{
			uc:          "communication timeout error overridden",
			interceptor: New(WithCommunicationErrorCode(http.StatusContinue)),
			err:         heimdall.ErrCommunicationTimeout,
			expGRPCCode: codes.DeadlineExceeded,
			expHTTPCode: http.StatusContinue,
		},
		{
			uc:          "communication timeout error verbose",
			interceptor: New(WithVerboseErrors(true)),
			err:         heimdall.ErrCommunicationTimeout,
			expGRPCCode: codes.DeadlineExceeded,
			expHTTPCode: http.StatusBadGateway,
			expBody:     "<p>communication timeout error</p>",
		},
		{
			uc:          "communication error default",
			interceptor: New(),
			err:         heimdall.ErrCommunication,
			expGRPCCode: codes.DeadlineExceeded,
			expHTTPCode: http.StatusBadGateway,
		},
		{
			uc:          "communication error overridden",
			interceptor: New(WithCommunicationErrorCode(http.StatusContinue)),
			err:         heimdall.ErrCommunication,
			expGRPCCode: codes.DeadlineExceeded,
			expHTTPCode: http.StatusContinue,
		},
		{
			uc:          "communication error verbose",
			interceptor: New(WithVerboseErrors(true)),
			err:         heimdall.ErrCommunication,
			expGRPCCode: codes.DeadlineExceeded,
			expHTTPCode: http.StatusBadGateway,
			expBody:     "<p>communication error</p>",
		},
		{
			uc:          "precondition error default",
			interceptor: New(),
			err:         heimdall.ErrArgument,
			expGRPCCode: codes.InvalidArgument,
			expHTTPCode: http.StatusBadRequest,
		},
		{
			uc:          "precondition error overridden",
			interceptor: New(WithPreconditionErrorCode(http.StatusContinue)),
			err:         heimdall.ErrArgument,
			expGRPCCode: codes.InvalidArgument,
			expHTTPCode: http.StatusContinue,
		},
		{
			uc:          "precondition error verbose",
			interceptor: New(WithVerboseErrors(true)),
			err:         heimdall.ErrArgument,
			expGRPCCode: codes.InvalidArgument,
			expHTTPCode: http.StatusBadRequest,
			expBody:     "<p>argument error</p>",
		},
		{
			uc:          "method error default",
			interceptor: New(),
			err:         heimdall.ErrMethodNotAllowed,
			expGRPCCode: codes.InvalidArgument,
			expHTTPCode: http.StatusMethodNotAllowed,
		},
		{
			uc:          "method error overridden",
			interceptor: New(WithMethodErrorCode(http.StatusContinue)),
			err:         heimdall.ErrMethodNotAllowed,
			expGRPCCode: codes.InvalidArgument,
			expHTTPCode: http.StatusContinue,
		},
		{
			uc:          "method error verbose",
			interceptor: New(WithVerboseErrors(true)),
			err:         heimdall.ErrMethodNotAllowed,
			expGRPCCode: codes.InvalidArgument,
			expHTTPCode: http.StatusMethodNotAllowed,
			expBody:     "<p>method not allowed</p>",
		},
		{
			uc:          "no rule error default",
			interceptor: New(),
			err:         heimdall.ErrNoRuleFound,
			expGRPCCode: codes.NotFound,
			expHTTPCode: http.StatusNotFound,
		},
		{
			uc:          "no rule error overridden",
			interceptor: New(WithNoRuleErrorCode(http.StatusContinue)),
			err:         heimdall.ErrNoRuleFound,
			expGRPCCode: codes.NotFound,
			expHTTPCode: http.StatusContinue,
		},
		{
			uc:          "no rule error verbose",
			interceptor: New(WithVerboseErrors(true)),
			err:         heimdall.ErrNoRuleFound,
			expGRPCCode: codes.NotFound,
			expHTTPCode: http.StatusNotFound,
			expBody:     "<p>no rule found</p>",
		},
		{
			uc:          "redirect error",
			interceptor: New(),
			err:         &heimdall.RedirectError{RedirectTo: "http://foo.local", Code: http.StatusFound},
			expGRPCCode: codes.FailedPrecondition,
			expHTTPCode: http.StatusFound,
		},
		{
			uc:          "redirect error verbose",
			interceptor: New(WithVerboseErrors(true)),
			err:         &heimdall.RedirectError{RedirectTo: "http://foo.local", Code: http.StatusFound},
			expGRPCCode: codes.FailedPrecondition,
			expHTTPCode: http.StatusFound,
		},
		{
			uc:          "internal error default",
			interceptor: New(),
			err:         heimdall.ErrInternal,
			expGRPCCode: codes.Internal,
			expHTTPCode: http.StatusInternalServerError,
		},
		{
			uc:          "internal error overridden",
			interceptor: New(WithInternalServerErrorCode(http.StatusContinue)),
			err:         heimdall.ErrInternal,
			expGRPCCode: codes.Internal,
			expHTTPCode: http.StatusContinue,
		},
		{
			uc:          "internal error verbose",
			interceptor: New(WithVerboseErrors(true)),
			err:         heimdall.ErrInternal,
			expGRPCCode: codes.Internal,
			expHTTPCode: http.StatusInternalServerError,
			expBody:     "<p>internal error</p>",
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			lis := bufconn.Listen(1024 * 1024)
			handler := &mocks.MockHandler{}
			bufDialer := func(context.Context, string) (net.Conn, error) { return lis.Dial() }
			conn, err := grpc.DialContext(context.Background(), "bufnet",
				grpc.WithContextDialer(bufDialer),
				grpc.WithTransportCredentials(insecure.NewCredentials()))
			require.NoError(t, err)

			defer conn.Close()

			if tc.err != nil {
				handler.On("Check", mock.Anything, mock.Anything).Return(nil, tc.err)
			} else {
				handler.On("Check", mock.Anything, mock.Anything).Return(&envoy_auth.CheckResponse{
					Status: &status.Status{Code: int32(tc.expGRPCCode)},
					HttpResponse: &envoy_auth.CheckResponse_OkResponse{
						OkResponse: &envoy_auth.OkHttpResponse{},
					},
				}, nil)
			}

			srv := grpc.NewServer(grpc.UnaryInterceptor(tc.interceptor))
			envoy_auth.RegisterAuthorizationServer(srv, handler)

			go func() {
				srv.Serve(lis)
			}()

			client := envoy_auth.NewAuthorizationClient(conn)

			// WHEN
			resp, err := client.Check(context.Background(), &envoy_auth.CheckRequest{
				Attributes: &envoy_auth.AttributeContext{
					Request: &envoy_auth.AttributeContext_Request{
						Http: &envoy_auth.AttributeContext_HttpRequest{
							Body:   "foo",
							Method: http.MethodPost,
							Path:   "/foobar",
						},
					},
				},
			})

			// THEN
			srv.Stop()
			require.NoError(t, err)

			assert.Equal(t, int32(tc.expGRPCCode), resp.GetStatus().GetCode())

			if tc.err != nil {
				deniedResp := resp.GetDeniedResponse()
				require.NotNil(t, deniedResp)
				assert.Equal(t, tc.expHTTPCode, deniedResp.GetStatus().GetCode())
				assert.Equal(t, tc.expBody, deniedResp.GetBody())
			}
		})
	}
}
