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

package otelmetrics

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
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	rpc_status "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	mocks2 "github.com/dadrus/heimdall/internal/handler/middleware/grpc/mocks"
)

func attributeValue(set attribute.Set, key attribute.Key) attribute.Value {
	if res, present := set.Value(key); present {
		return res
	}

	return attribute.Value{}
}

func TestHandlerObserveKnownRequests(t *testing.T) {
	for _, tc := range []struct {
		uc            string
		configureMock func(t *testing.T, srv *mocks2.MockHandler)
		assert        func(t *testing.T, rm *metricdata.ResourceMetrics)
	}{
		{
			uc: "metrics for successful request",
			configureMock: func(t *testing.T, handler *mocks2.MockHandler) {
				t.Helper()

				handler.On("Check", mock.Anything, mock.Anything).Return(&envoy_auth.CheckResponse{
					Status: &rpc_status.Status{Code: int32(envoy_type.StatusCode_OK)},
					HttpResponse: &envoy_auth.CheckResponse_OkResponse{
						OkResponse: &envoy_auth.OkHttpResponse{},
					},
				}, nil)
			},
			assert: func(t *testing.T, rm *metricdata.ResourceMetrics) {
				t.Helper()

				require.Len(t, rm.ScopeMetrics, 1)

				metrics := rm.ScopeMetrics[0]
				assert.Equal(t, "github.com/dadrus/heimdall/internal/handler/middleware/grpc/otelmetrics",
					metrics.Scope.Name)
				require.Len(t, metrics.Metrics, 1)

				activeRequestsMetric := metrics.Metrics[0]
				assert.Equal(t, "rpc.server.active_requests", activeRequestsMetric.Name)
				assert.Equal(t, "Measures the number of concurrent RPC requests that are currently in-flight.",
					activeRequestsMetric.Description)

				activeRequests := activeRequestsMetric.Data.(metricdata.Sum[float64]) // nolint: forcetypeassert
				assert.False(t, activeRequests.IsMonotonic)
				require.Len(t, activeRequests.DataPoints, 1)
				require.InDelta(t, float64(0), activeRequests.DataPoints[0].Value, 0.00)
				require.Equal(t, 9, activeRequests.DataPoints[0].Attributes.Len())
				assert.Equal(t, "foobar",
					attributeValue(activeRequests.DataPoints[0].Attributes, "service.subsystem").AsString())
				assert.Equal(t, "zab",
					attributeValue(activeRequests.DataPoints[0].Attributes, "baz").AsString())
				assert.Equal(t, "Check",
					attributeValue(activeRequests.DataPoints[0].Attributes, "rpc.method").AsString())
				assert.Equal(t, "envoy.service.auth.v3.Authorization",
					attributeValue(activeRequests.DataPoints[0].Attributes, "rpc.service").AsString())
				assert.Equal(t, "grpc",
					attributeValue(activeRequests.DataPoints[0].Attributes, "rpc.system").AsString())
				assert.Equal(t, "heimdall.local",
					attributeValue(activeRequests.DataPoints[0].Attributes, "server.address").AsString())
				assert.True(t, activeRequests.DataPoints[0].Attributes.HasValue("server.port"))
				assert.True(t, activeRequests.DataPoints[0].Attributes.HasValue(semconv.NetSockPeerAddrKey))
				assert.True(t, activeRequests.DataPoints[0].Attributes.HasValue(semconv.NetSockPeerPortKey))
			},
		},
		{
			uc: "metrics for request which failed with 403",
			configureMock: func(t *testing.T, handler *mocks2.MockHandler) {
				t.Helper()

				handler.On("Check", mock.Anything, mock.Anything).Return(&envoy_auth.CheckResponse{
					Status: &rpc_status.Status{Code: int32(envoy_type.StatusCode_Forbidden)},
					HttpResponse: &envoy_auth.CheckResponse_DeniedResponse{
						DeniedResponse: &envoy_auth.DeniedHttpResponse{
							Status: &envoy_type.HttpStatus{Code: envoy_type.StatusCode_Forbidden},
						},
					},
				}, nil)
			},
			assert: func(t *testing.T, rm *metricdata.ResourceMetrics) {
				t.Helper()

				require.Len(t, rm.ScopeMetrics, 1)

				metrics := rm.ScopeMetrics[0]
				assert.Equal(t, "github.com/dadrus/heimdall/internal/handler/middleware/grpc/otelmetrics",
					metrics.Scope.Name)
				require.Len(t, metrics.Metrics, 1)

				activeRequestsMetric := metrics.Metrics[0]
				assert.Equal(t, "rpc.server.active_requests", activeRequestsMetric.Name)
				assert.Equal(t, "Measures the number of concurrent RPC requests that are currently in-flight.",
					activeRequestsMetric.Description)

				activeRequests := activeRequestsMetric.Data.(metricdata.Sum[float64]) // nolint: forcetypeassert
				assert.False(t, activeRequests.IsMonotonic)
				require.Len(t, activeRequests.DataPoints, 1)
				require.InDelta(t, float64(0), activeRequests.DataPoints[0].Value, 0.00)
				require.Equal(t, 9, activeRequests.DataPoints[0].Attributes.Len())
				assert.Equal(t, "foobar",
					attributeValue(activeRequests.DataPoints[0].Attributes, "service.subsystem").AsString())
				assert.Equal(t, "zab",
					attributeValue(activeRequests.DataPoints[0].Attributes, "baz").AsString())
				assert.Equal(t, "Check",
					attributeValue(activeRequests.DataPoints[0].Attributes, "rpc.method").AsString())
				assert.Equal(t, "envoy.service.auth.v3.Authorization",
					attributeValue(activeRequests.DataPoints[0].Attributes, "rpc.service").AsString())
				assert.Equal(t, "grpc",
					attributeValue(activeRequests.DataPoints[0].Attributes, "rpc.system").AsString())
				assert.Equal(t, "heimdall.local",
					attributeValue(activeRequests.DataPoints[0].Attributes, "server.address").AsString())
				assert.True(t, activeRequests.DataPoints[0].Attributes.HasValue("server.port"))
				assert.True(t, activeRequests.DataPoints[0].Attributes.HasValue(semconv.NetSockPeerAddrKey))
				assert.True(t, activeRequests.DataPoints[0].Attributes.HasValue(semconv.NetSockPeerPortKey))
			},
		},
		{
			uc: "metrics for request with server raising an error",
			configureMock: func(t *testing.T, handler *mocks2.MockHandler) {
				t.Helper()

				handler.On("Check", mock.Anything, mock.Anything).
					Return(nil, status.Error(codes.FailedPrecondition, "test error"))
			},
			assert: func(t *testing.T, rm *metricdata.ResourceMetrics) {
				t.Helper()

				require.Len(t, rm.ScopeMetrics, 1)

				metrics := rm.ScopeMetrics[0]
				assert.Equal(t, "github.com/dadrus/heimdall/internal/handler/middleware/grpc/otelmetrics",
					metrics.Scope.Name)
				require.Len(t, metrics.Metrics, 1)

				activeRequestsMetric := metrics.Metrics[0]
				assert.Equal(t, "rpc.server.active_requests", activeRequestsMetric.Name)
				assert.Equal(t, "Measures the number of concurrent RPC requests that are currently in-flight.",
					activeRequestsMetric.Description)

				activeRequests := activeRequestsMetric.Data.(metricdata.Sum[float64]) // nolint: forcetypeassert
				assert.False(t, activeRequests.IsMonotonic)
				require.Len(t, activeRequests.DataPoints, 1)
				require.InDelta(t, float64(0), activeRequests.DataPoints[0].Value, 0.00)
				require.Equal(t, 9, activeRequests.DataPoints[0].Attributes.Len())
				assert.Equal(t, "foobar",
					attributeValue(activeRequests.DataPoints[0].Attributes, "service.subsystem").AsString())
				assert.Equal(t, "zab",
					attributeValue(activeRequests.DataPoints[0].Attributes, "baz").AsString())
				assert.Equal(t, "Check",
					attributeValue(activeRequests.DataPoints[0].Attributes, "rpc.method").AsString())
				assert.Equal(t, "envoy.service.auth.v3.Authorization",
					attributeValue(activeRequests.DataPoints[0].Attributes, "rpc.service").AsString())
				assert.Equal(t, "grpc",
					attributeValue(activeRequests.DataPoints[0].Attributes, "rpc.system").AsString())
				assert.Equal(t, "heimdall.local",
					attributeValue(activeRequests.DataPoints[0].Attributes, "server.address").AsString())
				assert.True(t, activeRequests.DataPoints[0].Attributes.HasValue("server.port"))
				assert.True(t, activeRequests.DataPoints[0].Attributes.HasValue(semconv.NetSockPeerAddrKey))
				assert.True(t, activeRequests.DataPoints[0].Attributes.HasValue(semconv.NetSockPeerPortKey))
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			exp := metric.NewManualReader()

			meterProvider := metric.NewMeterProvider(
				metric.WithResource(resource.Default()),
				metric.WithReader(exp),
			)

			lis := bufconn.Listen(1024 * 1024)
			handler := &mocks2.MockHandler{}
			conn, err := grpc.NewClient("passthrough://bufnet",
				grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
				grpc.WithTransportCredentials(insecure.NewCredentials()))
			require.NoError(t, err)

			defer conn.Close()

			tc.configureMock(t, handler)

			srv := grpc.NewServer(grpc.UnaryInterceptor(New(
				WithMeterProvider(meterProvider),
				WithSubsystem("foobar"),
				WithAttributes(attribute.Key("baz").String("zab")),
				WithServerName("heimdall.local:8080"),
			).UnaryServerInterceptor()))
			envoy_auth.RegisterAuthorizationServer(srv, handler)

			go func() {
				srv.Serve(lis)
			}()

			client := envoy_auth.NewAuthorizationClient(conn)

			// WHEN
			// we're not interested in the response and the error
			client.Check(context.Background(), &envoy_auth.CheckRequest{
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
			srv.Stop()

			var rm metricdata.ResourceMetrics

			err = exp.Collect(context.TODO(), &rm)
			require.NoError(t, err)

			tc.assert(t, &rm)
			handler.AssertExpectations(t)
		})
	}
}

func TestHandlerObserveUnknownRequests(t *testing.T) {
	// GIVEN
	exp := metric.NewManualReader()

	meterProvider := metric.NewMeterProvider(
		metric.WithResource(resource.Default()),
		metric.WithReader(exp),
	)

	lis := bufconn.Listen(1024 * 1024)
	handler := &mocks2.MockHandler{}
	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)

	defer conn.Close()

	metricsIntercepter := New(
		WithMeterProvider(meterProvider),
		WithSubsystem("foobar"),
		WithAttributes(attribute.Key("baz").String("zab")),
		WithServerName(":8080"),
	)
	srv := grpc.NewServer(
		grpc.UnknownServiceHandler(func(_ any, _ grpc.ServerStream) error {
			return status.Error(codes.Unknown, "unknown service or method")
		}),
		grpc.StreamInterceptor(metricsIntercepter.StreamServerInterceptor()))

	envoy_auth.RegisterAuthorizationServer(srv, handler)

	go func() {
		srv.Serve(lis)
	}()

	client := mocks2.NewTestClient(conn)

	// WHEN
	// we're not interested in the response and the error
	_, err = client.Test(context.Background(), &mocks2.TestRequest{})

	// THEN
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown service or method")
	srv.Stop()

	var rm metricdata.ResourceMetrics

	err = exp.Collect(context.TODO(), &rm)
	require.NoError(t, err)
	handler.AssertExpectations(t)

	require.Len(t, rm.ScopeMetrics, 1)

	metrics := rm.ScopeMetrics[0]
	assert.Equal(t, "github.com/dadrus/heimdall/internal/handler/middleware/grpc/otelmetrics",
		metrics.Scope.Name)
	require.Len(t, metrics.Metrics, 1)

	activeRequestsMetric := metrics.Metrics[0]
	assert.Equal(t, "rpc.server.active_requests", activeRequestsMetric.Name)
	assert.Equal(t, "Measures the number of concurrent RPC requests that are currently in-flight.",
		activeRequestsMetric.Description)

	activeRequests := activeRequestsMetric.Data.(metricdata.Sum[float64]) // nolint: forcetypeassert
	assert.False(t, activeRequests.IsMonotonic)
	require.Len(t, activeRequests.DataPoints, 1)
	require.InDelta(t, float64(0), activeRequests.DataPoints[0].Value, 0.00)
	require.Equal(t, 9, activeRequests.DataPoints[0].Attributes.Len())
	assert.Equal(t, "foobar",
		attributeValue(activeRequests.DataPoints[0].Attributes, "service.subsystem").AsString())
	assert.Equal(t, "zab",
		attributeValue(activeRequests.DataPoints[0].Attributes, "baz").AsString())
	assert.Equal(t, "Test",
		attributeValue(activeRequests.DataPoints[0].Attributes, "rpc.method").AsString())
	assert.Equal(t, "test.Test",
		attributeValue(activeRequests.DataPoints[0].Attributes, "rpc.service").AsString())
	assert.Equal(t, "grpc",
		attributeValue(activeRequests.DataPoints[0].Attributes, "rpc.system").AsString())
	assert.Equal(t, "127.0.0.1",
		attributeValue(activeRequests.DataPoints[0].Attributes, "server.address").AsString())
	assert.True(t, activeRequests.DataPoints[0].Attributes.HasValue("server.port"))
	assert.True(t, activeRequests.DataPoints[0].Attributes.HasValue(semconv.NetSockPeerAddrKey))
	assert.True(t, activeRequests.DataPoints[0].Attributes.HasValue(semconv.NetSockPeerPortKey))
}
