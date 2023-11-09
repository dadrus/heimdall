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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/justinas/alice"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
)

func attributeValue(set attribute.Set, key attribute.Key) attribute.Value {
	if res, present := set.Value(key); present {
		return res
	}

	return attribute.Value{}
}

func TestHandlerExecution(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		path   string
		method string
		assert func(t *testing.T, rm *metricdata.ResourceMetrics)
	}{
		{
			uc:     "metrics for filtered request",
			path:   "/filtered",
			method: http.MethodGet,
			assert: func(t *testing.T, rm *metricdata.ResourceMetrics) {
				t.Helper()

				assert.Empty(t, rm.ScopeMetrics)
			},
		},
		{
			uc:     "metrics for successful request",
			path:   "/test",
			method: http.MethodGet,
			assert: func(t *testing.T, rm *metricdata.ResourceMetrics) {
				t.Helper()

				require.Len(t, rm.ScopeMetrics, 1)

				metrics := rm.ScopeMetrics[0]
				assert.Equal(t, "github.com/dadrus/heimdall/internal/handler/middleware/http/otelmetrics",
					metrics.Scope.Name)

				require.Len(t, metrics.Metrics, 1)

				activeRequestsMetric := metrics.Metrics[0]
				assert.Equal(t, "http.server.active_requests", activeRequestsMetric.Name)
				assert.Equal(t, "Measures the number of concurrent HTTP requests that are currently in-flight.",
					activeRequestsMetric.Description)
				activeRequests := activeRequestsMetric.Data.(metricdata.Sum[float64]) // nolint: forcetypeassert
				assert.False(t, activeRequests.IsMonotonic)
				require.Len(t, activeRequests.DataPoints, 1)
				require.InDelta(t, float64(0), activeRequests.DataPoints[0].Value, 0.00)
				require.Equal(t, 7, activeRequests.DataPoints[0].Attributes.Len())
				assert.Equal(t, "foobar",
					attributeValue(activeRequests.DataPoints[0].Attributes, "service.subsystem").AsString())
				assert.Equal(t, "zab",
					attributeValue(activeRequests.DataPoints[0].Attributes, "baz").AsString())
				assert.Equal(t, "1.1",
					attributeValue(activeRequests.DataPoints[0].Attributes, "http.flavor").AsString())
				assert.Equal(t, http.MethodGet,
					attributeValue(activeRequests.DataPoints[0].Attributes, "http.method").AsString())
				assert.Equal(t, "http",
					attributeValue(activeRequests.DataPoints[0].Attributes, "http.scheme").AsString())
				assert.Equal(t, "127.0.0.1",
					attributeValue(activeRequests.DataPoints[0].Attributes, "net.host.name").AsString())
				assert.True(t, activeRequests.DataPoints[0].Attributes.HasValue("net.host.port"))
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

			srv := httptest.NewServer(
				alice.New(
					New(
						WithMeterProvider(meterProvider),
						WithAttributes(attribute.Key("baz").String("zab")),
						WithSubsystem("foobar"),
						WithOperationFilter(func(req *http.Request) bool { return req.URL.Path != "/filtered" }),
					),
				).ThenFunc(func(rw http.ResponseWriter, req *http.Request) {
					switch req.URL.Path {
					case "/test":
						fallthrough
					case "/filtered":
						rw.WriteHeader(http.StatusOK)
					default:
						rw.WriteHeader(http.StatusNotFound)
					}
				}),
			)

			defer srv.Close()

			req, err := http.NewRequestWithContext(
				context.Background(),
				tc.method,
				fmt.Sprintf("%s%s", srv.URL, tc.path),
				nil,
			)
			require.NoError(t, err)

			// WHEN
			resp, err := srv.Client().Do(req)
			require.NoError(t, err)

			defer resp.Body.Close()

			var rm metricdata.ResourceMetrics

			err = exp.Collect(context.TODO(), &rm)
			require.NoError(t, err)

			// THEN
			tc.assert(t, &rm)
		})
	}
}
