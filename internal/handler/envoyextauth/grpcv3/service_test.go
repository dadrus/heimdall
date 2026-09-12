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
	"time"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/inhies/go-bytesize"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
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
					Connections: config.DefaultIngressConnections(),
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

	t.Run("limits concurrent streams per connection", func(t *testing.T) {
		// GIVEN
		conf := &config.Configuration{}
		conf.Serve.Requests.Headers.MaxSize = 64 * bytesize.KB
		conf.Serve.Connections.Streams.MaxConcurrent = 1

		exec := mocks3.NewExecutorMock(t)

		requestEntered := make(chan struct{}, 2)
		releaseRequest := make(chan struct{})

		released := false
		releaseRequests := func() {
			if !released {
				close(releaseRequest)
				released = true
			}
		}
		t.Cleanup(releaseRequests)

		exec.EXPECT().
			Execute(mock.Anything).
			Times(2).
			Run(func(_ mock.Arguments) {
				requestEntered <- struct{}{}

				<-releaseRequest
			}).
			Return(pipeline.ErrNoRuleFound)

		srv := newService(
			conf,
			mocks.NewCacheMock(t),
			log.Logger,
			exec,
		)

		listener := bufconn.Listen(8 * 1024 * 1024)
		t.Cleanup(func() {
			_ = listener.Close()
		})

		t.Cleanup(srv.Stop)

		go func() {
			_ = srv.Serve(listener)
		}()

		conn, err := grpc.NewClient(
			"passthrough:///bufnet",
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
				return listener.Dial()
			}),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = conn.Close()
		})

		client := envoy_auth.NewAuthorizationClient(conn)

		createRequest := func() *envoy_auth.CheckRequest {
			return &envoy_auth.CheckRequest{
				Attributes: &envoy_auth.AttributeContext{
					Request: &envoy_auth.AttributeContext_Request{
						Http: &envoy_auth.AttributeContext_HttpRequest{
							Method: http.MethodGet,
							Scheme: "http",
							Host:   "example.com",
							Path:   "/",
						},
					},
				},
			}
		}

		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()

		firstDone := make(chan error, 1)

		go func() {
			_, err := client.Check(ctx, createRequest())
			firstDone <- err
		}()

		// Wait until the first stream has reached the server and occupies
		// the only available concurrent-stream slot.
		select {
		case <-requestEntered:
		case <-ctx.Done():
			require.FailNow(t, "first request did not reach the server")
		}

		secondDone := make(chan error, 1)
		secondStarted := make(chan struct{})

		go func() {
			close(secondStarted)

			_, err := client.Check(ctx, createRequest())
			secondDone <- err
		}()

		<-secondStarted

		select {
		case <-requestEntered:
			// unexpected
		case <-time.After(100 * time.Millisecond):
		}

		// THEN
		// The second RPC uses the same ClientConn and must not reach the
		// server while the first stream still occupies the only slot.
		select {
		case <-requestEntered:
			releaseRequests()

			require.FailNow(
				t,
				"second request reached the server while stream capacity was exhausted",
			)
		case <-time.After(100 * time.Millisecond):
		}

		// WHEN
		releaseRequests()

		// THEN
		// Releasing the first stream must make capacity available for the
		// second one.
		select {
		case <-requestEntered:
		case <-ctx.Done():
			require.FailNow(t, "second request did not reach the server after capacity was released")
		}

		require.NoError(t, <-firstDone)
		require.NoError(t, <-secondDone)
	})

	t.Run("rejects request if maximum number of requests is in flight", func(t *testing.T) {
		// GIVEN
		conf := &config.Configuration{}
		conf.Serve.Requests.Headers.MaxSize = 64 * bytesize.KB
		conf.Serve.Requests.MaxInFlight = 1
		conf.Serve.Connections.Streams.MaxConcurrent = 100
		conf.Serve.Respond.With.TooManyRequests.Code = http.StatusServiceUnavailable

		exec := mocks3.NewExecutorMock(t)

		requestEntered := make(chan struct{}, 2)
		releaseRequest := make(chan struct{})

		released := false
		releaseRequests := func() {
			if !released {
				close(releaseRequest)
				released = true
			}
		}

		exec.EXPECT().Execute(mock.Anything).
			Run(func(_ pipeline.ExecutionContext) {
				requestEntered <- struct{}{}

				<-releaseRequest
			}).
			Return(pipeline.ErrNoRuleFound)

		srv := newService(conf, mocks.NewCacheMock(t), log.Logger, exec)

		listener := bufconn.Listen(8 * 1024 * 1024)

		go func() {
			_ = srv.Serve(listener)
		}()

		conn, err := grpc.NewClient(
			"passthrough:///bufnet",
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
				return listener.Dial()
			}),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		require.NoError(t, err)

		t.Cleanup(func() {
			releaseRequests()
			_ = conn.Close()
			srv.Stop()
			_ = listener.Close()
		})

		client := envoy_auth.NewAuthorizationClient(conn)

		createRequest := func() *envoy_auth.CheckRequest {
			return &envoy_auth.CheckRequest{
				Attributes: &envoy_auth.AttributeContext{
					Request: &envoy_auth.AttributeContext_Request{
						Http: &envoy_auth.AttributeContext_HttpRequest{
							Method: http.MethodGet,
							Scheme: "http",
							Host:   "example.com",
							Path:   "/",
						},
					},
				},
			}
		}

		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()

		firstResponse := make(chan *envoy_auth.CheckResponse, 1)
		firstError := make(chan error, 1)

		go func() {
			resp, err := client.Check(ctx, createRequest())

			firstResponse <- resp
			firstError <- err
		}()

		select {
		case <-requestEntered:
		case <-ctx.Done():
			require.FailNow(t, "first request did not reach pipeline")
		}

		var (
			secondResponse *envoy_auth.CheckResponse
			secondErr      error
		)

		secondDone := make(chan struct{})

		// WHEN
		go func() {
			defer close(secondDone)

			secondResponse, secondErr = client.Check(ctx, createRequest())
		}()

		// THEN
		select {
		case <-requestEntered:
			require.FailNow(
				t,
				"second request reached pipeline while maximum number of requests was in flight",
			)

		case <-secondDone:
			require.NoError(t, secondErr)
			require.NotNil(t, secondResponse)

			assert.Equal(
				t,
				int32(codes.ResourceExhausted),
				secondResponse.GetStatus().GetCode(),
			)

			deniedResponse := secondResponse.GetDeniedResponse()
			require.NotNil(t, deniedResponse)

			assert.Equal(
				t,
				typev3.StatusCode(http.StatusServiceUnavailable),
				deniedResponse.GetStatus().GetCode(),
			)
			assert.Empty(t, deniedResponse.GetBody())
			assert.Empty(t, deniedResponse.GetHeaders())

		case <-ctx.Done():
			require.FailNow(t, "second request was not rejected immediately")
		}

		// WHEN
		releaseRequests()

		// THEN
		select {
		case err := <-firstError:
			require.NoError(t, err)
		case <-ctx.Done():
			require.FailNow(t, "first request did not complete")
		}

		select {
		case resp := <-firstResponse:
			require.NotNil(t, resp)

			assert.Equal(
				t,
				int32(codes.NotFound),
				resp.GetStatus().GetCode(),
			)

			deniedResponse := resp.GetDeniedResponse()
			require.NotNil(t, deniedResponse)

			assert.Equal(
				t,
				typev3.StatusCode(http.StatusNotFound),
				deniedResponse.GetStatus().GetCode(),
			)

		case <-ctx.Done():
			require.FailNow(t, "first response was not received")
		}
	})
}

func TestGRPCHeaderLimit(t *testing.T) {
	// GIVEN
	conf := newGRPCTestConfig()
	conf.Serve.Requests.Headers.MaxSize = 512

	exec := mocks3.NewExecutorMock(t)
	client := newGRPCTestClient(t, conf, exec)
	ctx := metadata.AppendToOutgoingContext(
		t.Context(),
		"x-oversized-metadata",
		strings.Repeat("x", 2*1024),
	)

	// WHEN
	_, err := client.Check(ctx, newGRPCTestRequest())

	// THEN
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
	assert.Contains(t, err.Error(), "header list size")
}

func TestUnaryRPCLifetime(t *testing.T) {
	t.Run("http io timeouts do not become an rpc lifetime", func(t *testing.T) {
		// GIVEN
		conf := newGRPCTestConfig()
		conf.Serve.Requests.ReadTimeout = time.Millisecond
		conf.Serve.Requests.Body.ReadIdleTimeout = time.Millisecond
		conf.Serve.Responses.WriteTimeout = time.Millisecond
		conf.Serve.Responses.WriteIdleTimeout = time.Millisecond

		exec := mocks3.NewExecutorMock(t)
		exec.EXPECT().Execute(mock.Anything).RunAndReturn(func(ctx pipeline.ExecutionContext) error {
			select {
			case <-time.After(25 * time.Millisecond):
				return nil
			case <-ctx.Context().Done():
				return ctx.Context().Err()
			}
		})

		client := newGRPCTestClient(t, conf, exec)
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()

		// WHEN
		resp, err := client.Check(ctx, newGRPCTestRequest())

		// THEN
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, int32(codes.OK), resp.GetStatus().GetCode())
	})

	t.Run("client deadline propagates into the pipeline context", func(t *testing.T) {
		// GIVEN
		conf := newGRPCTestConfig()
		exec := mocks3.NewExecutorMock(t)

		type observedContext struct {
			deadline time.Time
			ok       bool
		}

		observed := make(chan observedContext, 1)

		exec.EXPECT().Execute(mock.Anything).RunAndReturn(func(ctx pipeline.ExecutionContext) error {
			deadline, ok := ctx.Context().Deadline()
			observed <- observedContext{
				deadline: deadline,
				ok:       ok,
			}

			<-ctx.Context().Done()

			return ctx.Context().Err()
		})

		client := newGRPCTestClient(t, conf, exec)
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()

		clientDeadline, ok := ctx.Deadline()
		require.True(t, ok)

		// WHEN
		_, err := client.Check(ctx, newGRPCTestRequest())

		// THEN
		require.Error(t, err)
		assert.Equal(t, codes.DeadlineExceeded, status.Code(err))

		select {
		case observedContext := <-observed:
			require.True(t, observedContext.ok)
			assert.WithinDuration(t, clientDeadline, observedContext.deadline, 10*time.Millisecond)
		case <-time.After(time.Second):
			require.FailNow(t, "pipeline did not observe the rpc deadline")
		}
	})

	t.Run("client cancellation propagates into the pipeline context", func(t *testing.T) {
		// GIVEN
		conf := newGRPCTestConfig()
		exec := mocks3.NewExecutorMock(t)
		entered := make(chan struct{})
		observed := make(chan error, 1)

		exec.EXPECT().Execute(mock.Anything).RunAndReturn(func(ctx pipeline.ExecutionContext) error {
			close(entered)
			<-ctx.Context().Done()
			observed <- ctx.Context().Err()

			return ctx.Context().Err()
		})

		client := newGRPCTestClient(t, conf, exec)
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)

		go func() {
			_, err := client.Check(ctx, newGRPCTestRequest())
			result <- err
		}()

		select {
		case <-entered:
		case <-time.After(time.Second):
			cancel()
			require.FailNow(t, "request did not reach the pipeline")
		}

		// WHEN
		cancel()

		// THEN
		select {
		case err := <-result:
			require.Error(t, err)
			assert.Equal(t, codes.Canceled, status.Code(err))
		case <-time.After(time.Second):
			require.FailNow(t, "rpc did not complete after cancellation")
		}

		select {
		case observedErr := <-observed:
			require.ErrorIs(t, observedErr, context.Canceled)
		case <-time.After(time.Second):
			require.FailNow(t, "pipeline did not observe the rpc cancellation")
		}
	})
}

func newGRPCTestConfig() *config.Configuration {
	return &config.Configuration{
		Serve: config.ServeConfig{
			Connections: config.DefaultIngressConnections(),
			Requests: config.IngressRequests{
				Headers: config.IngressRequestHeaders{
					MaxSize: 64 * bytesize.KB,
				},
			},
		},
	}
}

func newGRPCTestClient(
	t *testing.T,
	conf *config.Configuration,
	exec pipeline.Executor,
) envoy_auth.AuthorizationClient {
	t.Helper()

	listener := bufconn.Listen(8 * 1024 * 1024)
	srv := newService(conf, mocks.NewCacheMock(t), log.Logger, exec)

	go func() {
		_ = srv.Serve(listener)
	}()

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = conn.Close()
		srv.Stop()
		_ = listener.Close()
	})

	return envoy_auth.NewAuthorizationClient(conn)
}

func newGRPCTestRequest() *envoy_auth.CheckRequest {
	return &envoy_auth.CheckRequest{
		Attributes: &envoy_auth.AttributeContext{
			Request: &envoy_auth.AttributeContext_Request{
				Http: &envoy_auth.AttributeContext_HttpRequest{
					Method: http.MethodGet,
					Scheme: "http",
					Host:   "example.com",
					Path:   "/",
				},
			},
		},
	}
}
