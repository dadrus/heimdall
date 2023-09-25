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

package prometheus

import (
	"context"
	"net"
	"net/http"
	"testing"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	rpc_status "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	mocks2 "github.com/dadrus/heimdall/internal/handler/middleware/grpc/mocks"
)

func metricForType(metrics []*dto.MetricFamily, metricType *dto.MetricType) *dto.MetricFamily {
	for _, m := range metrics {
		if *m.Type == *metricType {
			return m
		}
	}

	return nil
}

func getLabel(labels []*dto.LabelPair, name string) string {
	for _, label := range labels {
		if label.GetName() == name {
			return label.GetValue()
		}
	}

	return ""
}

func TestHandlerObserveKnownRequests(t *testing.T) {
	for _, tc := range []struct {
		uc            string
		configureMock func(t *testing.T, srv *mocks2.MockHandler)
		assert        func(t *testing.T, metrics []*dto.MetricFamily)
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
			assert: func(t *testing.T, metrics []*dto.MetricFamily) {
				t.Helper()

				assert.Len(t, metrics, 3)

				histMetric := metricForType(metrics, dto.MetricType_HISTOGRAM.Enum())
				assert.Equal(t, "foo_bar_request_duration_seconds", histMetric.GetName())
				assert.Equal(t, "Duration of all requests by tunneled HTTP status code, service and method, "+
					"as well as by GRPC method and status code.",
					histMetric.GetHelp())
				require.Len(t, histMetric.Metric, 1)
				assert.Equal(t, "zab", getLabel(histMetric.Metric[0].Label, "baz"))
				assert.Equal(t, "foobar", getLabel(histMetric.Metric[0].Label, "service"))
				assert.Equal(t, "0", getLabel(histMetric.Metric[0].Label, "grpc_code"))
				assert.Equal(t, "/envoy.service.auth.v3.Authorization/Check",
					getLabel(histMetric.Metric[0].Label, "grpc_method"))
				assert.Equal(t, "POST", getLabel(histMetric.Metric[0].Label, "http_method"))
				assert.Equal(t, "/test", getLabel(histMetric.Metric[0].Label, "http_path"))
				assert.Equal(t, "200", getLabel(histMetric.Metric[0].Label, "http_code"))
				require.Len(t, histMetric.Metric[0].Histogram.Bucket, 21)

				gaugeMetric := metricForType(metrics, dto.MetricType_GAUGE.Enum())
				assert.Equal(t, "foo_bar_requests_in_progress_total", gaugeMetric.GetName())
				assert.Equal(t, "All the requests in progress by tunneled HTTP method, "+
					"as well as by GRPC method.", gaugeMetric.GetHelp())
				require.Len(t, gaugeMetric.Metric, 1)
				assert.Equal(t, "zab", getLabel(gaugeMetric.Metric[0].Label, "baz"))
				assert.Equal(t, "foobar", getLabel(gaugeMetric.Metric[0].Label, "service"))
				assert.Equal(t, "/envoy.service.auth.v3.Authorization/Check",
					getLabel(gaugeMetric.Metric[0].Label, "grpc_method"))
				assert.Equal(t, "POST", getLabel(gaugeMetric.Metric[0].Label, "http_method"))
				require.Equal(t, 0.0, gaugeMetric.Metric[0].Gauge.GetValue())

				counterMetric := metricForType(metrics, dto.MetricType_COUNTER.Enum())
				assert.Equal(t, "foo_bar_requests_total", counterMetric.GetName())
				assert.Equal(t, "Count all requests by tunneled HTTP status code, service and method,"+
					" as well as by GRPC method and status code.",
					counterMetric.GetHelp())
				require.Len(t, counterMetric.Metric, 1)
				assert.Equal(t, "zab", getLabel(counterMetric.Metric[0].Label, "baz"))
				assert.Equal(t, "foobar", getLabel(counterMetric.Metric[0].Label, "service"))
				assert.Equal(t, "0", getLabel(histMetric.Metric[0].Label, "grpc_code"))
				assert.Equal(t, "/envoy.service.auth.v3.Authorization/Check",
					getLabel(histMetric.Metric[0].Label, "grpc_method"))
				assert.Equal(t, "POST", getLabel(counterMetric.Metric[0].Label, "http_method"))
				assert.Equal(t, "/test", getLabel(counterMetric.Metric[0].Label, "http_path"))
				assert.Equal(t, "200", getLabel(counterMetric.Metric[0].Label, "http_code"))
				require.Equal(t, 1.0, counterMetric.Metric[0].Counter.GetValue())
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
			assert: func(t *testing.T, metrics []*dto.MetricFamily) {
				t.Helper()

				assert.Len(t, metrics, 3)

				histMetric := metricForType(metrics, dto.MetricType_HISTOGRAM.Enum())
				assert.Equal(t, "foo_bar_request_duration_seconds", histMetric.GetName())
				assert.Equal(t, "Duration of all requests by tunneled HTTP status code, service and method, "+
					"as well as by GRPC method and status code.", histMetric.GetHelp())
				require.Len(t, histMetric.Metric, 1)
				assert.Equal(t, "zab", getLabel(histMetric.Metric[0].Label, "baz"))
				assert.Equal(t, "foobar", getLabel(histMetric.Metric[0].Label, "service"))
				assert.Equal(t, "0", getLabel(histMetric.Metric[0].Label, "grpc_code"))
				assert.Equal(t, "/envoy.service.auth.v3.Authorization/Check",
					getLabel(histMetric.Metric[0].Label, "grpc_method"))
				assert.Equal(t, "POST", getLabel(histMetric.Metric[0].Label, "http_method"))
				assert.Equal(t, "/test", getLabel(histMetric.Metric[0].Label, "http_path"))
				assert.Equal(t, "403", getLabel(histMetric.Metric[0].Label, "http_code"))
				require.Len(t, histMetric.Metric[0].Histogram.Bucket, 21)

				gaugeMetric := metricForType(metrics, dto.MetricType_GAUGE.Enum())
				assert.Equal(t, "foo_bar_requests_in_progress_total", gaugeMetric.GetName())
				assert.Equal(t, "All the requests in progress by tunneled HTTP method, "+
					"as well as by GRPC method.", gaugeMetric.GetHelp())
				require.Len(t, gaugeMetric.Metric, 1)
				assert.Equal(t, "zab", getLabel(gaugeMetric.Metric[0].Label, "baz"))
				assert.Equal(t, "foobar", getLabel(gaugeMetric.Metric[0].Label, "service"))
				assert.Equal(t, "/envoy.service.auth.v3.Authorization/Check",
					getLabel(histMetric.Metric[0].Label, "grpc_method"))
				assert.Equal(t, "POST", getLabel(gaugeMetric.Metric[0].Label, "http_method"))
				require.Equal(t, 0.0, gaugeMetric.Metric[0].Gauge.GetValue())

				counterMetric := metricForType(metrics, dto.MetricType_COUNTER.Enum())
				assert.Equal(t, "foo_bar_requests_total", counterMetric.GetName())
				assert.Equal(t, "Count all requests by tunneled HTTP status code, service and method, "+
					"as well as by GRPC method and status code.", counterMetric.GetHelp())
				require.Len(t, counterMetric.Metric, 1)
				assert.Equal(t, "zab", getLabel(counterMetric.Metric[0].Label, "baz"))
				assert.Equal(t, "foobar", getLabel(counterMetric.Metric[0].Label, "service"))
				assert.Equal(t, "0", getLabel(histMetric.Metric[0].Label, "grpc_code"))
				assert.Equal(t, "/envoy.service.auth.v3.Authorization/Check",
					getLabel(histMetric.Metric[0].Label, "grpc_method"))
				assert.Equal(t, "POST", getLabel(counterMetric.Metric[0].Label, "http_method"))
				assert.Equal(t, "/test", getLabel(counterMetric.Metric[0].Label, "http_path"))
				assert.Equal(t, "403", getLabel(counterMetric.Metric[0].Label, "http_code"))
				require.Equal(t, 1.0, counterMetric.Metric[0].Counter.GetValue())
			},
		},
		{
			uc: "metrics for request with server raising an error",
			configureMock: func(t *testing.T, handler *mocks2.MockHandler) {
				t.Helper()

				handler.On("Check", mock.Anything, mock.Anything).
					Return(nil, status.Error(codes.FailedPrecondition, "test error"))
			},
			assert: func(t *testing.T, metrics []*dto.MetricFamily) {
				t.Helper()

				assert.Len(t, metrics, 3)

				histMetric := metricForType(metrics, dto.MetricType_HISTOGRAM.Enum())
				assert.Equal(t, "foo_bar_request_duration_seconds", histMetric.GetName())
				assert.Equal(t, "Duration of all requests by tunneled HTTP status code, service and method, "+
					"as well as by GRPC method and status code.", histMetric.GetHelp())
				require.Len(t, histMetric.Metric, 1)
				assert.Equal(t, "zab", getLabel(histMetric.Metric[0].Label, "baz"))
				assert.Equal(t, "foobar", getLabel(histMetric.Metric[0].Label, "service"))
				assert.Equal(t, "9", getLabel(histMetric.Metric[0].Label, "grpc_code"))
				assert.Equal(t, "/envoy.service.auth.v3.Authorization/Check",
					getLabel(histMetric.Metric[0].Label, "grpc_method"))
				assert.Equal(t, "POST", getLabel(histMetric.Metric[0].Label, "http_method"))
				assert.Equal(t, "/test", getLabel(histMetric.Metric[0].Label, "http_path"))
				assert.Equal(t, "unknown", getLabel(histMetric.Metric[0].Label, "http_code"))
				require.Len(t, histMetric.Metric[0].Histogram.Bucket, 21)

				gaugeMetric := metricForType(metrics, dto.MetricType_GAUGE.Enum())
				assert.Equal(t, "foo_bar_requests_in_progress_total", gaugeMetric.GetName())
				assert.Equal(t, "All the requests in progress by tunneled HTTP method, "+
					"as well as by GRPC method.", gaugeMetric.GetHelp())
				assert.Equal(t, "zab", getLabel(gaugeMetric.Metric[0].Label, "baz"))
				assert.Equal(t, "/envoy.service.auth.v3.Authorization/Check",
					getLabel(histMetric.Metric[0].Label, "grpc_method"))
				assert.Equal(t, "POST", getLabel(gaugeMetric.Metric[0].Label, "http_method"))
				assert.Equal(t, "foobar", getLabel(gaugeMetric.Metric[0].Label, "service"))
				require.Equal(t, 0.0, gaugeMetric.Metric[0].Gauge.GetValue())

				counterMetric := metricForType(metrics, dto.MetricType_COUNTER.Enum())
				assert.Equal(t, "foo_bar_requests_total", counterMetric.GetName())
				assert.Equal(t, "Count all requests by tunneled HTTP status code, service and method, "+
					"as well as by GRPC method and status code.", counterMetric.GetHelp())
				require.Len(t, counterMetric.Metric, 1)
				assert.Equal(t, "zab", getLabel(counterMetric.Metric[0].Label, "baz"))
				assert.Equal(t, "foobar", getLabel(counterMetric.Metric[0].Label, "service"))
				assert.Equal(t, "9", getLabel(histMetric.Metric[0].Label, "grpc_code"))
				assert.Equal(t, "/envoy.service.auth.v3.Authorization/Check",
					getLabel(histMetric.Metric[0].Label, "grpc_method"))
				assert.Equal(t, "POST", getLabel(counterMetric.Metric[0].Label, "http_method"))
				assert.Equal(t, "/test", getLabel(counterMetric.Metric[0].Label, "http_path"))
				assert.Equal(t, "unknown", getLabel(counterMetric.Metric[0].Label, "http_code"))
				require.Equal(t, 1.0, counterMetric.Metric[0].Counter.GetValue())
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			registry := prometheus.NewRegistry()
			lis := bufconn.Listen(1024 * 1024)
			handler := &mocks2.MockHandler{}
			conn, err := grpc.DialContext(context.Background(), "bufnet",
				grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
				grpc.WithTransportCredentials(insecure.NewCredentials()))
			require.NoError(t, err)

			defer conn.Close()

			tc.configureMock(t, handler)

			srv := grpc.NewServer(grpc.UnaryInterceptor(New(
				WithRegisterer(registry),
				WithNamespace("foo"),
				WithSubsystem("bar"),
				WithLabel("baz", "zab"),
				WithServiceName("foobar"),
			).Unary()))
			envoy_auth.RegisterAuthorizationServer(srv, handler)

			go func() {
				err = srv.Serve(lis)
				require.NoError(t, err)
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

			metrics, err := registry.Gather()
			require.NoError(t, err)

			tc.assert(t, metrics)
			handler.AssertExpectations(t)
		})
	}
}

func TestHandlerObserveUnknownRequests(t *testing.T) {
	// GIVEN
	registry := prometheus.NewRegistry()
	lis := bufconn.Listen(1024 * 1024)
	handler := &mocks2.MockHandler{}
	conn, err := grpc.DialContext(context.Background(), "bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)

	defer conn.Close()

	metricsIntercepter := New(
		WithRegisterer(registry),
		WithNamespace("foo"),
		WithSubsystem("bar"),
		WithLabel("baz", "zab"),
		WithServiceName("foobar"),
	)
	srv := grpc.NewServer(
		grpc.UnknownServiceHandler(func(srv interface{}, stream grpc.ServerStream) error {
			return status.Error(codes.Unknown, "unknown service or method")
		}),
		grpc.StreamInterceptor(metricsIntercepter.Stream()))

	envoy_auth.RegisterAuthorizationServer(srv, handler)

	go func() {
		err = srv.Serve(lis)
		require.NoError(t, err)
	}()

	client := mocks2.NewTestClient(conn)

	// WHEN
	// we're not interested in the response and the error
	_, err = client.Test(context.Background(), &mocks2.TestRequest{})

	// THEN
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown service or method")
	srv.Stop()

	metrics, err := registry.Gather()
	require.NoError(t, err)
	handler.AssertExpectations(t)

	assert.Len(t, metrics, 3)
	histMetric := metricForType(metrics, dto.MetricType_HISTOGRAM.Enum())
	assert.Equal(t, "foo_bar_request_duration_seconds", histMetric.GetName())
	assert.Equal(t, "Duration of all requests by tunneled HTTP status code, service and method, "+
		"as well as by GRPC method and status code.", histMetric.GetHelp())
	require.Len(t, histMetric.Metric, 1)
	assert.Equal(t, "zab", getLabel(histMetric.Metric[0].Label, "baz"))
	assert.Equal(t, "foobar", getLabel(histMetric.Metric[0].Label, "service"))
	assert.Equal(t, "2", getLabel(histMetric.Metric[0].Label, "grpc_code"))
	assert.Equal(t, "/test.Test/Test",
		getLabel(histMetric.Metric[0].Label, "grpc_method"))
	assert.Equal(t, "unknown", getLabel(histMetric.Metric[0].Label, "http_method"))
	assert.Equal(t, "unknown", getLabel(histMetric.Metric[0].Label, "http_path"))
	assert.Equal(t, "unknown", getLabel(histMetric.Metric[0].Label, "http_code"))
	require.Len(t, histMetric.Metric[0].Histogram.Bucket, 21)

	gaugeMetric := metricForType(metrics, dto.MetricType_GAUGE.Enum())
	assert.Equal(t, "foo_bar_requests_in_progress_total", gaugeMetric.GetName())
	assert.Equal(t, "All the requests in progress by tunneled HTTP method, "+
		"as well as by GRPC method.", gaugeMetric.GetHelp())
	assert.Equal(t, "zab", getLabel(gaugeMetric.Metric[0].Label, "baz"))
	assert.Equal(t, "/test.Test/Test",
		getLabel(histMetric.Metric[0].Label, "grpc_method"))
	assert.Equal(t, "unknown", getLabel(gaugeMetric.Metric[0].Label, "http_method"))
	assert.Equal(t, "foobar", getLabel(gaugeMetric.Metric[0].Label, "service"))
	require.Equal(t, 0.0, gaugeMetric.Metric[0].Gauge.GetValue())

	counterMetric := metricForType(metrics, dto.MetricType_COUNTER.Enum())
	assert.Equal(t, "foo_bar_requests_total", counterMetric.GetName())
	assert.Equal(t, "Count all requests by tunneled HTTP status code, service and method, "+
		"as well as by GRPC method and status code.", counterMetric.GetHelp())
	require.Len(t, counterMetric.Metric, 1)
	assert.Equal(t, "zab", getLabel(counterMetric.Metric[0].Label, "baz"))
	assert.Equal(t, "foobar", getLabel(counterMetric.Metric[0].Label, "service"))
	assert.Equal(t, "2", getLabel(histMetric.Metric[0].Label, "grpc_code"))
	assert.Equal(t, "/test.Test/Test",
		getLabel(histMetric.Metric[0].Label, "grpc_method"))
	assert.Equal(t, "unknown", getLabel(counterMetric.Metric[0].Label, "http_method"))
	assert.Equal(t, "unknown", getLabel(counterMetric.Metric[0].Label, "http_path"))
	assert.Equal(t, "unknown", getLabel(counterMetric.Metric[0].Label, "http_code"))
	require.Equal(t, 1.0, counterMetric.Metric[0].Counter.GetValue())
}
