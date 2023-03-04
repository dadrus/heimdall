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

package accesslog

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/goccy/go-json"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	rpc_status "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/dadrus/heimdall/internal/accesscontext"
	"github.com/dadrus/heimdall/internal/handler/envoyextauth/grpcv3/middleware/mocks"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestAccessLogInterceptorForKnownService(t *testing.T) {
	otel.SetTracerProvider(sdktrace.NewTracerProvider())
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}))

	parentCtx := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{1}, SpanID: trace.SpanID{2}, TraceFlags: trace.FlagsSampled,
	})

	for _, tc := range []struct {
		uc              string
		outgoingContext func(t *testing.T) context.Context
		configureMock   func(t *testing.T, m *mocks.MockHandler)
		assert          func(t *testing.T, logEvent1, logEvent2 map[string]any)
	}{
		{
			uc: "without tracing, x-* header and errors",
			outgoingContext: func(t *testing.T) context.Context {
				t.Helper()

				return context.Background()
			},
			configureMock: func(t *testing.T, m *mocks.MockHandler) {
				t.Helper()

				m.On("Check",
					mock.MatchedBy(
						func(ctx context.Context) bool {
							accesscontext.SetSubject(ctx, "foo")

							return true
						},
					),
					mock.Anything,
				).Return(
					&envoy_auth.CheckResponse{Status: &rpc_status.Status{Code: int32(envoy_type.StatusCode_OK)}},
					nil,
				)
			},
			assert: func(t *testing.T, logEvent1, logEvent2 map[string]any) {
				t.Helper()

				require.Len(t, logEvent1, 7)
				assert.Equal(t, "info", logEvent1["level"])
				assert.Contains(t, logEvent1, "_tx_start")
				assert.Contains(t, logEvent1, "_client_ip")
				assert.Equal(t, "/envoy.service.auth.v3.Authorization/Check", logEvent1["_grpc_method"])
				assert.Contains(t, logEvent1, "_trace_id")
				assert.Contains(t, logEvent1, "_trace_id")
				assert.NotEqual(t, parentCtx.TraceID().String(), logEvent1["_trace_id"])
				assert.NotEqual(t, parentCtx.SpanID().String(), logEvent1["_parent_id"])
				assert.Equal(t, "TX started", logEvent1["message"])

				require.Len(t, logEvent2, 10)
				assert.Equal(t, "info", logEvent2["level"])
				assert.Contains(t, logEvent2, "_tx_start")
				assert.Contains(t, logEvent2, "_tx_duration_ms")
				assert.Contains(t, logEvent2, "_client_ip")
				assert.Equal(t, logEvent1["_grpc_method"], logEvent2["_grpc_method"])
				assert.Contains(t, logEvent2, "_trace_id")
				assert.Contains(t, logEvent2, "_trace_id")
				assert.Equal(t, logEvent2["_trace_id"], logEvent2["_trace_id"])
				assert.Equal(t, logEvent2["_parent_id"], logEvent2["_parent_id"])
				assert.Equal(t, true, logEvent2["_access_granted"])
				assert.Equal(t, "foo", logEvent2["_subject"])
				assert.Equal(t, "TX finished", logEvent2["message"])
			},
		},
		{
			uc: "with tracing, x-* header and error",
			outgoingContext: func(t *testing.T) context.Context {
				t.Helper()

				md := map[string]string{
					"x-forwarded-for": "127.0.0.1",
					"forwarded":       "for=127.0.0.1",
				}

				otel.GetTextMapPropagator().Inject(
					trace.ContextWithRemoteSpanContext(context.Background(), parentCtx),
					propagation.MapCarrier(md))

				return metadata.NewOutgoingContext(context.Background(), metadata.New(md))
			},
			configureMock: func(t *testing.T, m *mocks.MockHandler) {
				t.Helper()

				m.On("Check", mock.Anything, mock.Anything).
					Return(nil, fmt.Errorf("test error")) // nolint: goerr113
			},
			assert: func(t *testing.T, logEvent1, logEvent2 map[string]any) {
				t.Helper()

				require.Len(t, logEvent1, 10)
				assert.Equal(t, "info", logEvent1["level"])
				assert.Contains(t, logEvent1, "_tx_start")
				assert.Contains(t, logEvent1, "_client_ip")
				assert.Equal(t, "/envoy.service.auth.v3.Authorization/Check", logEvent1["_grpc_method"])
				assert.Contains(t, logEvent1, "_span_id")
				assert.Equal(t, parentCtx.TraceID().String(), logEvent1["_trace_id"])
				assert.Equal(t, parentCtx.SpanID().String(), logEvent1["_parent_id"])
				assert.Equal(t, "for=127.0.0.1", logEvent1["_forwarded"])
				assert.Equal(t, "127.0.0.1", logEvent1["_x_forwarded_for"])
				assert.Equal(t, "TX started", logEvent1["message"])

				require.Len(t, logEvent2, 13)
				assert.Equal(t, "info", logEvent2["level"])
				assert.Contains(t, logEvent2, "_tx_start")
				assert.Contains(t, logEvent2, "_tx_duration_ms")
				assert.Contains(t, logEvent2, "_client_ip")
				assert.Equal(t, logEvent1["_grpc_method"], logEvent2["_grpc_method"])
				assert.Equal(t, logEvent2["_trace_id"], logEvent2["_trace_id"])
				assert.Equal(t, logEvent2["_parent_id"], logEvent2["_parent_id"])
				assert.Equal(t, logEvent2["_span_id"], logEvent2["_span_id"])
				assert.Equal(t, false, logEvent2["_access_granted"])
				assert.Equal(t, "test error", logEvent2["error"])
				assert.Equal(t, "for=127.0.0.1", logEvent1["_forwarded"])
				assert.Equal(t, "127.0.0.1", logEvent1["_x_forwarded_for"])
				assert.Equal(t, "TX finished", logEvent2["message"])
			},
		},
		{
			uc: "without tracing and x-* header, but with subject and error set on context",
			outgoingContext: func(t *testing.T) context.Context {
				t.Helper()

				return context.Background()
			},
			configureMock: func(t *testing.T, m *mocks.MockHandler) {
				t.Helper()

				m.On("Check",
					mock.MatchedBy(
						func(ctx context.Context) bool {
							accesscontext.SetSubject(ctx, "bar")
							accesscontext.SetError(ctx, fmt.Errorf("test error")) // nolint: goerr113

							return true
						},
					),
					mock.Anything,
				).Return(
					&envoy_auth.CheckResponse{Status: &rpc_status.Status{Code: int32(envoy_type.StatusCode_Forbidden)}},
					nil,
				)
			},
			assert: func(t *testing.T, logEvent1, logEvent2 map[string]any) {
				t.Helper()

				require.Len(t, logEvent1, 7)
				assert.Equal(t, "info", logEvent1["level"])
				assert.Contains(t, logEvent1, "_tx_start")
				assert.Contains(t, logEvent1, "_client_ip")
				assert.Equal(t, "/envoy.service.auth.v3.Authorization/Check", logEvent1["_grpc_method"])
				assert.Contains(t, logEvent1, "_trace_id")
				assert.Contains(t, logEvent1, "_trace_id")
				assert.NotEqual(t, parentCtx.TraceID().String(), logEvent1["_trace_id"])
				assert.NotEqual(t, parentCtx.SpanID().String(), logEvent1["_parent_id"])
				assert.Equal(t, "TX started", logEvent1["message"])

				require.Len(t, logEvent2, 11)
				assert.Equal(t, "info", logEvent2["level"])
				assert.Contains(t, logEvent2, "_tx_start")
				assert.Contains(t, logEvent2, "_tx_duration_ms")
				assert.Contains(t, logEvent2, "_client_ip")
				assert.Equal(t, logEvent1["_grpc_method"], logEvent2["_grpc_method"])
				assert.Contains(t, logEvent2, "_trace_id")
				assert.Contains(t, logEvent2, "_trace_id")
				assert.Equal(t, logEvent2["_trace_id"], logEvent2["_trace_id"])
				assert.Equal(t, logEvent2["_parent_id"], logEvent2["_parent_id"])
				assert.Equal(t, false, logEvent2["_access_granted"])
				assert.Equal(t, "bar", logEvent2["_subject"])
				assert.Equal(t, "test error", logEvent2["error"])
				assert.Equal(t, "TX finished", logEvent2["message"])
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			var (
				logLine1 map[string]any
				logLine2 map[string]any
			)

			lis := bufconn.Listen(1024 * 1024)
			tb := &testsupport.TestingLog{TB: t}
			logger := zerolog.New(zerolog.TestWriter{T: tb})
			handler := &mocks.MockHandler{}
			conn, err := grpc.DialContext(context.Background(), "bufnet",
				grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
				grpc.WithTransportCredentials(insecure.NewCredentials()))
			require.NoError(t, err)

			defer conn.Close()

			tc.configureMock(t, handler)

			srv := grpc.NewServer(
				grpc.ChainUnaryInterceptor(
					otelgrpc.UnaryServerInterceptor(),
					New(logger).Unary(),
				),
			)
			envoy_auth.RegisterAuthorizationServer(srv, handler)

			go func() {
				err = srv.Serve(lis)
				require.NoError(t, err)
			}()

			client := envoy_auth.NewAuthorizationClient(conn)

			// WHEN
			// nolint: errcheck
			client.Check(tc.outgoingContext(t), &envoy_auth.CheckRequest{
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

			events := strings.Split(tb.CollectedLog(), "}")
			require.Len(t, events, 3)

			require.NoError(t, json.Unmarshal([]byte(events[0]+"}"), &logLine1))
			require.NoError(t, json.Unmarshal([]byte(events[1]+"}"), &logLine2))

			tc.assert(t, logLine1, logLine2)
			handler.AssertExpectations(t)
		})
	}
}

func TestAccessLogInterceptorForUnknownService(t *testing.T) {
	otel.SetTracerProvider(sdktrace.NewTracerProvider())
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}))

	var (
		logEvent1 map[string]any
		logEvent2 map[string]any
	)

	lis := bufconn.Listen(1024 * 1024)
	tb := &testsupport.TestingLog{TB: t}
	logger := zerolog.New(zerolog.TestWriter{T: tb})
	handler := &mocks.MockHandler{}
	bufDialer := func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}
	conn, err := grpc.DialContext(context.Background(), "bufnet",
		grpc.WithContextDialer(bufDialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)

	defer conn.Close()

	srv := grpc.NewServer(
		grpc.UnknownServiceHandler(func(srv interface{}, stream grpc.ServerStream) error {
			return status.Error(codes.Unknown, "unknown service or method")
		}),
		grpc.ChainStreamInterceptor(
			otelgrpc.StreamServerInterceptor(),
			New(logger).Stream(),
		),
	)
	envoy_auth.RegisterAuthorizationServer(srv, handler)

	go func() {
		err = srv.Serve(lis)
		require.NoError(t, err)
	}()

	client := mocks.NewTestClient(conn)

	// WHEN
	// nolint: errcheck
	_, err = client.Test(context.Background(), &mocks.TestRequest{})

	// THEN
	require.Error(t, err)
	srv.Stop()
	handler.AssertExpectations(t)

	events := strings.Split(tb.CollectedLog(), "}")
	require.Len(t, events, 3)

	require.NoError(t, json.Unmarshal([]byte(events[0]+"}"), &logEvent1))
	require.NoError(t, json.Unmarshal([]byte(events[1]+"}"), &logEvent2))

	require.Len(t, logEvent1, 7)
	assert.Equal(t, "info", logEvent1["level"])
	assert.Contains(t, logEvent1, "_tx_start")
	assert.Contains(t, logEvent1, "_client_ip")
	assert.Equal(t, "/test.Test/Test", logEvent1["_grpc_method"])
	assert.Contains(t, logEvent1, "_trace_id")
	assert.Contains(t, logEvent1, "_trace_id")
	assert.Equal(t, "TX started", logEvent1["message"])

	require.Len(t, logEvent2, 10)
	assert.Equal(t, "info", logEvent2["level"])
	assert.Contains(t, logEvent2, "_tx_start")
	assert.Contains(t, logEvent2, "_tx_duration_ms")
	assert.Contains(t, logEvent2, "_client_ip")
	assert.Equal(t, logEvent1["_grpc_method"], logEvent2["_grpc_method"])
	assert.Contains(t, logEvent2, "_trace_id")
	assert.Contains(t, logEvent2, "_trace_id")
	assert.Equal(t, logEvent2["_trace_id"], logEvent2["_trace_id"])
	assert.Equal(t, logEvent2["_parent_id"], logEvent2["_parent_id"])
	assert.Equal(t, false, logEvent2["_access_granted"])
	assert.Contains(t, logEvent2["error"], "unknown service or method")
	assert.Equal(t, "TX finished", logEvent2["message"])
}
