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
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"

	"github.com/dadrus/heimdall/internal/accesscontext"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

type mockHandler struct {
	mock.Mock
}

func (m *mockHandler) Check(ctx context.Context, req *envoy_auth.CheckRequest) (*envoy_auth.CheckResponse, error) {
	args := m.Called(ctx, req)

	if val := args.Get(0); val != nil {
		// nolint: forcetypeassert
		return val.(*envoy_auth.CheckResponse), nil
	}

	return nil, args.Error(1)
}

func TestAccessLogInterceptor(t *testing.T) {
	otel.SetTracerProvider(sdktrace.NewTracerProvider())
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}))

	parentCtx := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{1}, SpanID: trace.SpanID{2}, TraceFlags: trace.FlagsSampled,
	})

	for _, tc := range []struct {
		uc              string
		outgoingContext func(t *testing.T) context.Context
		configureMock   func(t *testing.T, m *mockHandler)
		assert          func(t *testing.T, logEvent1, logEvent2 map[string]any)
	}{
		{
			uc: "without tracing, x-* header and errors",
			outgoingContext: func(t *testing.T) context.Context {
				t.Helper()

				return context.Background()
			},
			configureMock: func(t *testing.T, m *mockHandler) {
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
					&envoy_auth.CheckResponse{Status: &status.Status{Code: int32(envoy_type.StatusCode_OK)}},
					nil,
				)
			},
			assert: func(t *testing.T, logEvent1, logEvent2 map[string]any) {
				t.Helper()

				require.Len(t, logEvent1, 7)
				assert.Equal(t, "info", logEvent1["level"])
				assert.Contains(t, logEvent1, "_tx_start")
				assert.Contains(t, logEvent1, "_peer")
				assert.Equal(t, "/envoy.service.auth.v3.Authorization/Check", logEvent1["_request"])
				assert.Contains(t, logEvent1, "_trace_id")
				assert.Contains(t, logEvent1, "_trace_id")
				assert.NotEqual(t, parentCtx.TraceID().String(), logEvent1["_trace_id"])
				assert.NotEqual(t, parentCtx.SpanID().String(), logEvent1["_parent_id"])
				assert.Equal(t, "TX started", logEvent1["message"])

				require.Len(t, logEvent2, 10)
				assert.Equal(t, "info", logEvent2["level"])
				assert.Contains(t, logEvent2, "_tx_start")
				assert.Contains(t, logEvent2, "_tx_duration_ms")
				assert.Contains(t, logEvent2, "_peer")
				assert.Equal(t, logEvent1["_request"], logEvent2["_request"])
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
			configureMock: func(t *testing.T, m *mockHandler) {
				t.Helper()

				m.On("Check", mock.Anything, mock.Anything).
					Return(nil, fmt.Errorf("test error")) // nolint: goerr113
			},
			assert: func(t *testing.T, logEvent1, logEvent2 map[string]any) {
				t.Helper()

				require.Len(t, logEvent1, 10)
				assert.Equal(t, "info", logEvent1["level"])
				assert.Contains(t, logEvent1, "_tx_start")
				assert.Contains(t, logEvent1, "_peer")
				assert.Equal(t, "/envoy.service.auth.v3.Authorization/Check", logEvent1["_request"])
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
				assert.Contains(t, logEvent2, "_peer")
				assert.Equal(t, logEvent1["_request"], logEvent2["_request"])
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
			configureMock: func(t *testing.T, m *mockHandler) {
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
					&envoy_auth.CheckResponse{Status: &status.Status{Code: int32(envoy_type.StatusCode_Forbidden)}},
					nil,
				)
			},
			assert: func(t *testing.T, logEvent1, logEvent2 map[string]any) {
				t.Helper()

				require.Len(t, logEvent1, 7)
				assert.Equal(t, "info", logEvent1["level"])
				assert.Contains(t, logEvent1, "_tx_start")
				assert.Contains(t, logEvent1, "_peer")
				assert.Equal(t, "/envoy.service.auth.v3.Authorization/Check", logEvent1["_request"])
				assert.Contains(t, logEvent1, "_trace_id")
				assert.Contains(t, logEvent1, "_trace_id")
				assert.NotEqual(t, parentCtx.TraceID().String(), logEvent1["_trace_id"])
				assert.NotEqual(t, parentCtx.SpanID().String(), logEvent1["_parent_id"])
				assert.Equal(t, "TX started", logEvent1["message"])

				require.Len(t, logEvent2, 11)
				assert.Equal(t, "info", logEvent2["level"])
				assert.Contains(t, logEvent2, "_tx_start")
				assert.Contains(t, logEvent2, "_tx_duration_ms")
				assert.Contains(t, logEvent2, "_peer")
				assert.Equal(t, logEvent1["_request"], logEvent2["_request"])
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
			handler := &mockHandler{}
			bufDialer := func(context.Context, string) (net.Conn, error) {
				return lis.Dial()
			}
			conn, err := grpc.DialContext(context.Background(), "bufnet",
				grpc.WithContextDialer(bufDialer),
				grpc.WithTransportCredentials(insecure.NewCredentials()))
			require.NoError(t, err)

			defer conn.Close()

			tc.configureMock(t, handler)

			srv := grpc.NewServer(
				grpc.ChainUnaryInterceptor(
					otelgrpc.UnaryServerInterceptor(),
					New(logger),
				),
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

			events := strings.Split(tb.CollectedLog(), "}")
			require.Len(t, events, 3)

			require.NoError(t, json.Unmarshal([]byte(events[0]+"}"), &logLine1))
			require.NoError(t, json.Unmarshal([]byte(events[1]+"}"), &logLine2))

			tc.assert(t, logLine1, logLine2)
			handler.AssertExpectations(t)
		})
	}
}
