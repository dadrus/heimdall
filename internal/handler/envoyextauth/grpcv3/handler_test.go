package grpcv3

import (
	"context"
	"net"
	"net/http"
	"testing"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	mocks2 "github.com/dadrus/heimdall/internal/rules/rule/mocks"
)

func TestHandleDecisionEndpointRequest(t *testing.T) {
	for _, tc := range []struct {
		uc             string
		configureMocks func(t *testing.T, exec *mocks2.ExecutorMock)
		assertResponse func(t *testing.T, err error, response *envoy_auth.CheckResponse)
	}{
		{
			uc: "no rules configured",
			configureMocks: func(t *testing.T, exec *mocks2.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(mock.Anything).Return(nil, heimdall.ErrNoRuleFound)
			},
			assertResponse: func(t *testing.T, err error, response *envoy_auth.CheckResponse) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, int32(codes.NotFound), response.Status.Code)

				deniedResponse := response.GetDeniedResponse()
				require.NotNil(t, deniedResponse)
				assert.Equal(t, typev3.StatusCode(http.StatusNotFound), deniedResponse.Status.Code)
				assert.Len(t, deniedResponse.Body, 0)
				assert.Empty(t, deniedResponse.Headers)
			},
		},
		{
			uc: "rule doesn't match method",
			configureMocks: func(t *testing.T, exec *mocks2.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(mock.Anything).Return(nil, heimdall.ErrMethodNotAllowed)
			},
			assertResponse: func(t *testing.T, err error, response *envoy_auth.CheckResponse) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, int32(codes.InvalidArgument), response.Status.Code)

				deniedResponse := response.GetDeniedResponse()
				require.NotNil(t, deniedResponse)
				assert.Equal(t, typev3.StatusCode(http.StatusMethodNotAllowed), deniedResponse.Status.Code)
				assert.Len(t, deniedResponse.Body, 0)
				assert.Empty(t, deniedResponse.Headers)
			},
		},
		{
			uc: "rule execution fails with authentication error",
			configureMocks: func(t *testing.T, exec *mocks2.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(mock.Anything).Return(nil, heimdall.ErrAuthentication)
			},
			assertResponse: func(t *testing.T, err error, response *envoy_auth.CheckResponse) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, int32(codes.Unauthenticated), response.Status.Code)

				deniedResponse := response.GetDeniedResponse()
				require.NotNil(t, deniedResponse)
				assert.Equal(t, typev3.StatusCode(http.StatusUnauthorized), deniedResponse.Status.Code)
				assert.Len(t, deniedResponse.Body, 0)
				assert.Empty(t, deniedResponse.Headers)
			},
		},
		{
			uc: "rule execution fails with authorization error",
			configureMocks: func(t *testing.T, exec *mocks2.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(mock.Anything).Return(nil, heimdall.ErrAuthorization)
			},
			assertResponse: func(t *testing.T, err error, response *envoy_auth.CheckResponse) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, int32(codes.PermissionDenied), response.Status.Code)

				deniedResponse := response.GetDeniedResponse()
				require.NotNil(t, deniedResponse)
				assert.Equal(t, typev3.StatusCode(http.StatusForbidden), deniedResponse.Status.Code)
				assert.Len(t, deniedResponse.Body, 0)
				assert.Empty(t, deniedResponse.Headers)
			},
		},
		{
			uc: "rule execution fails with a redirect",
			configureMocks: func(t *testing.T, exec *mocks2.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(mock.Anything).Return(nil, &heimdall.RedirectError{
					Message:    "test redirect",
					Code:       http.StatusFound,
					RedirectTo: "http://foo.bar",
				})
			},
			assertResponse: func(t *testing.T, err error, response *envoy_auth.CheckResponse) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, int32(codes.FailedPrecondition), response.Status.Code)

				deniedResponse := response.GetDeniedResponse()
				require.NotNil(t, deniedResponse)
				assert.Equal(t, typev3.StatusCode(http.StatusFound), deniedResponse.Status.Code)
				assert.Len(t, deniedResponse.Body, 0)
				assert.Len(t, deniedResponse.Headers, 1)
				assert.Equal(t, "Location", deniedResponse.Headers[0].Header.Key)
				assert.Equal(t, "http://foo.bar", deniedResponse.Headers[0].Header.Value)
			},
		},
		{
			uc: "rule execution succeeds",
			configureMocks: func(t *testing.T, exec *mocks2.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(
					mock.MatchedBy(func(ctx heimdall.Context) bool {
						req := ctx.Request()

						return req.URL.Path == "/test" &&
							req.Method == http.MethodPost
					}),
				).Return(nil, nil)
			},
			assertResponse: func(t *testing.T, err error, response *envoy_auth.CheckResponse) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, int32(codes.OK), response.Status.Code)

				okResponse := response.GetOkResponse()
				require.NotNil(t, okResponse)
				assert.Empty(t, okResponse.Headers)
			},
		},
		{
			uc: "server panics and error does not contain traces",
			configureMocks: func(t *testing.T, exec *mocks2.ExecutorMock) {
				t.Helper()

				exec.EXPECT().Execute(mock.Anything).Panic("wuff")
			},
			assertResponse: func(t *testing.T, err error, response *envoy_auth.CheckResponse) {
				t.Helper()

				require.Error(t, err)
				assert.Equal(t, "rpc error: code = Internal desc = internal error", err.Error())
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			lis := bufconn.Listen(1024 * 1024)
			conn, err := grpc.DialContext(context.Background(), "bufnet",
				grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
				grpc.WithTransportCredentials(insecure.NewCredentials()))
			require.NoError(t, err)
			conf := &config.Configuration{Metrics: config.MetricsConfig{Enabled: true}}
			cch := mocks.NewCacheMock(t)
			exec := mocks2.NewExecutorMock(t)

			tc.configureMocks(t, exec)

			srv := newService(conf, prometheus.NewRegistry(), cch, log.Logger, exec, nil)

			defer srv.Stop()

			go func() {
				err := srv.Serve(lis)
				require.NoError(t, err)
			}()

			client := envoy_auth.NewAuthorizationClient(conn)

			// WHEN
			resp, err := client.Check(context.Background(), &envoy_auth.CheckRequest{
				Attributes: &envoy_auth.AttributeContext{
					Request: &envoy_auth.AttributeContext_Request{
						Http: &envoy_auth.AttributeContext_HttpRequest{
							Body:   "foo",
							Method: http.MethodPost,
							Path:   "/test",
						},
					},
				},
			})

			// THEN
			tc.assertResponse(t, err, resp)
		})
	}
}
