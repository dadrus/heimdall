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

package logger

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
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
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"

	"github.com/dadrus/heimdall/internal/handler/middleware/grpc/mocks"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestLoggerInterceptor(t *testing.T) {
	// GIVEN
	otel.SetTracerProvider(sdktrace.NewTracerProvider())
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}))

	parentCtx := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{1}, SpanID: trace.SpanID{2}, TraceFlags: trace.FlagsSampled,
	})

	for _, tc := range []struct {
		uc              string
		outgoingContext func(t *testing.T) context.Context
		assert          func(t *testing.T, logstring string)
	}{
		{
			uc: "without tracing",
			outgoingContext: func(t *testing.T) context.Context {
				t.Helper()

				return context.Background()
			},
			assert: func(t *testing.T, logstring string) {
				t.Helper()

				assert.Contains(t, logstring, "test called")
				assert.Contains(t, logstring, "_span_id")
				assert.Contains(t, logstring, "_trace_id")
				assert.NotContains(t, logstring, "_parent_id")

				var logData map[string]string
				require.NoError(t, json.Unmarshal([]byte(logstring), &logData))
				assert.NotEqual(t, parentCtx.TraceID().String(), logData["_trace_id"])
				assert.NotEqual(t, parentCtx.SpanID().String(), logData["_parent_id"])
			},
		},
		{
			uc: "with tracing",
			outgoingContext: func(t *testing.T) context.Context {
				t.Helper()

				md := map[string]string{}

				otel.GetTextMapPropagator().Inject(
					trace.ContextWithRemoteSpanContext(context.Background(), parentCtx),
					propagation.MapCarrier(md))

				return metadata.NewOutgoingContext(context.Background(), metadata.New(md))
			},
			assert: func(t *testing.T, logstring string) {
				t.Helper()

				assert.Contains(t, logstring, "test called")
				assert.Contains(t, logstring, "_span_id")
				assert.Contains(t, logstring, "_trace_id")
				assert.Contains(t, logstring, "_parent_id")

				var logData map[string]string
				require.NoError(t, json.Unmarshal([]byte(logstring), &logData))
				assert.Equal(t, parentCtx.TraceID().String(), logData["_trace_id"])
				assert.Equal(t, parentCtx.SpanID().String(), logData["_parent_id"])
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
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

			handler.On("Check", mock.MatchedBy(
				func(ctx context.Context) bool {
					zerolog.Ctx(ctx).Info().Msg("test called")

					return true
				},
			), mock.Anything).
				Return(nil, fmt.Errorf("test error"))

			srv := grpc.NewServer(
				grpc.StatsHandler(otelgrpc.NewServerHandler()),
				grpc.ChainUnaryInterceptor(New(logger)),
			)
			envoy_auth.RegisterAuthorizationServer(srv, handler)

			go func() {
				err = srv.Serve(lis)
				require.NoError(t, err)
			}()

			client := envoy_auth.NewAuthorizationClient(conn)

			// WHEN
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

			// THEN
			require.NoError(t, err)
			tc.assert(t, tb.CollectedLog())
		})
	}
}
