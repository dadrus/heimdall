// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestHandlerObserveRequests(t *testing.T) { //nolint:maintidx
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		req    *http.Request
		assert func(t *testing.T, metrics []*dto.MetricFamily)
	}{
		{
			uc:  "metrics for filtered request",
			req: httptest.NewRequest(http.MethodGet, "/filtered", nil),
			assert: func(t *testing.T, metrics []*dto.MetricFamily) {
				t.Helper()

				assert.Empty(t, metrics)
			},
		},
		{
			uc:  "metrics for successful request",
			req: httptest.NewRequest(http.MethodGet, "/test", nil),
			assert: func(t *testing.T, metrics []*dto.MetricFamily) {
				t.Helper()

				assert.Len(t, metrics, 3)

				histMetric := metricForType(metrics, dto.MetricType_HISTOGRAM.Enum())
				assert.Equal(t, "foo_bar_request_duration_seconds", histMetric.GetName())
				assert.Equal(t, "Duration of all requests by status code, method and path.",
					histMetric.GetHelp())
				require.Len(t, histMetric.Metric, 1)
				assert.Equal(t, "zab", getLabel(histMetric.Metric[0].Label, "baz"))
				assert.Equal(t, "GET", getLabel(histMetric.Metric[0].Label, "http_method"))
				assert.Equal(t, "/test", getLabel(histMetric.Metric[0].Label, "http_path"))
				assert.Equal(t, "foobar", getLabel(histMetric.Metric[0].Label, "service"))
				assert.Equal(t, "200", getLabel(histMetric.Metric[0].Label, "http_code"))
				require.Len(t, histMetric.Metric[0].Histogram.Bucket, 21)

				gaugeMetric := metricForType(metrics, dto.MetricType_GAUGE.Enum())
				assert.Equal(t, "foo_bar_requests_in_progress_total", gaugeMetric.GetName())
				assert.Equal(t, "All the requests in progress", gaugeMetric.GetHelp())
				require.Len(t, gaugeMetric.Metric, 1)
				assert.Equal(t, "zab", getLabel(gaugeMetric.Metric[0].Label, "baz"))
				assert.Equal(t, "GET", getLabel(gaugeMetric.Metric[0].Label, "http_method"))
				assert.Equal(t, "foobar", getLabel(gaugeMetric.Metric[0].Label, "service"))
				require.Equal(t, 0.0, gaugeMetric.Metric[0].Gauge.GetValue())

				counterMetric := metricForType(metrics, dto.MetricType_COUNTER.Enum())
				assert.Equal(t, "foo_bar_requests_total", counterMetric.GetName())
				assert.Equal(t, "Count all requests by status code, method and path.",
					counterMetric.GetHelp())
				require.Len(t, counterMetric.Metric, 1)
				assert.Equal(t, "zab", getLabel(counterMetric.Metric[0].Label, "baz"))
				assert.Equal(t, "GET", getLabel(counterMetric.Metric[0].Label, "http_method"))
				assert.Equal(t, "/test", getLabel(counterMetric.Metric[0].Label, "http_path"))
				assert.Equal(t, "foobar", getLabel(counterMetric.Metric[0].Label, "service"))
				assert.Equal(t, "200", getLabel(counterMetric.Metric[0].Label, "http_code"))
				require.Equal(t, 1.0, counterMetric.Metric[0].Counter.GetValue())
			},
		},
		{
			uc:  "metrics for request which failed with 500",
			req: httptest.NewRequest(http.MethodPost, "/test", nil),
			assert: func(t *testing.T, metrics []*dto.MetricFamily) {
				t.Helper()

				assert.Len(t, metrics, 3)

				histMetric := metricForType(metrics, dto.MetricType_HISTOGRAM.Enum())
				assert.Equal(t, "foo_bar_request_duration_seconds", histMetric.GetName())
				assert.Equal(t, "Duration of all requests by status code, method and path.",
					histMetric.GetHelp())
				require.Len(t, histMetric.Metric, 1)
				assert.Equal(t, "zab", getLabel(histMetric.Metric[0].Label, "baz"))
				assert.Equal(t, "POST", getLabel(histMetric.Metric[0].Label, "http_method"))
				assert.Equal(t, "/test", getLabel(histMetric.Metric[0].Label, "http_path"))
				assert.Equal(t, "foobar", getLabel(histMetric.Metric[0].Label, "service"))
				assert.Equal(t, "500", getLabel(histMetric.Metric[0].Label, "http_code"))
				require.Len(t, histMetric.Metric[0].Histogram.Bucket, 21)

				gaugeMetric := metricForType(metrics, dto.MetricType_GAUGE.Enum())
				assert.Equal(t, "foo_bar_requests_in_progress_total", gaugeMetric.GetName())
				assert.Equal(t, "All the requests in progress", gaugeMetric.GetHelp())
				require.Len(t, gaugeMetric.Metric, 1)
				assert.Equal(t, "zab", getLabel(gaugeMetric.Metric[0].Label, "baz"))
				assert.Equal(t, "POST", getLabel(gaugeMetric.Metric[0].Label, "http_method"))
				assert.Equal(t, "foobar", getLabel(gaugeMetric.Metric[0].Label, "service"))
				require.Equal(t, 0.0, gaugeMetric.Metric[0].Gauge.GetValue())

				counterMetric := metricForType(metrics, dto.MetricType_COUNTER.Enum())
				assert.Equal(t, "foo_bar_requests_total", counterMetric.GetName())
				assert.Equal(t, "Count all requests by status code, method and path.",
					counterMetric.GetHelp())
				require.Len(t, counterMetric.Metric, 1)
				assert.Equal(t, "zab", getLabel(counterMetric.Metric[0].Label, "baz"))
				assert.Equal(t, "POST", getLabel(counterMetric.Metric[0].Label, "http_method"))
				assert.Equal(t, "/test", getLabel(counterMetric.Metric[0].Label, "http_path"))
				assert.Equal(t, "foobar", getLabel(counterMetric.Metric[0].Label, "service"))
				assert.Equal(t, "500", getLabel(counterMetric.Metric[0].Label, "http_code"))
				require.Equal(t, 1.0, counterMetric.Metric[0].Counter.GetValue())
			},
		},
		{
			uc:  "metrics for request with server raising an error",
			req: httptest.NewRequest(http.MethodPatch, "/error", nil),
			assert: func(t *testing.T, metrics []*dto.MetricFamily) {
				t.Helper()

				assert.Len(t, metrics, 3)

				histMetric := metricForType(metrics, dto.MetricType_HISTOGRAM.Enum())
				assert.Equal(t, "foo_bar_request_duration_seconds", histMetric.GetName())
				assert.Equal(t, "Duration of all requests by status code, method and path.",
					histMetric.GetHelp())
				require.Len(t, histMetric.Metric, 1)
				assert.Equal(t, "zab", getLabel(histMetric.Metric[0].Label, "baz"))
				assert.Equal(t, "PATCH", getLabel(histMetric.Metric[0].Label, "http_method"))
				assert.Equal(t, "/error", getLabel(histMetric.Metric[0].Label, "http_path"))
				assert.Equal(t, "foobar", getLabel(histMetric.Metric[0].Label, "service"))
				assert.Equal(t, "410", getLabel(histMetric.Metric[0].Label, "http_code"))
				require.Len(t, histMetric.Metric[0].Histogram.Bucket, 21)

				gaugeMetric := metricForType(metrics, dto.MetricType_GAUGE.Enum())
				assert.Equal(t, "foo_bar_requests_in_progress_total", gaugeMetric.GetName())
				assert.Equal(t, "All the requests in progress", gaugeMetric.GetHelp())
				require.Len(t, gaugeMetric.Metric, 1)
				assert.Equal(t, "zab", getLabel(gaugeMetric.Metric[0].Label, "baz"))
				assert.Equal(t, "PATCH", getLabel(gaugeMetric.Metric[0].Label, "http_method"))
				assert.Equal(t, "foobar", getLabel(gaugeMetric.Metric[0].Label, "service"))
				require.Equal(t, 0.0, gaugeMetric.Metric[0].Gauge.GetValue())

				counterMetric := metricForType(metrics, dto.MetricType_COUNTER.Enum())
				assert.Equal(t, "foo_bar_requests_total", counterMetric.GetName())
				assert.Equal(t, "Count all requests by status code, method and path.",
					counterMetric.GetHelp())
				require.Len(t, counterMetric.Metric, 1)
				assert.Equal(t, "zab", getLabel(counterMetric.Metric[0].Label, "baz"))
				assert.Equal(t, "PATCH", getLabel(counterMetric.Metric[0].Label, "http_method"))
				assert.Equal(t, "/error", getLabel(counterMetric.Metric[0].Label, "http_path"))
				assert.Equal(t, "foobar", getLabel(counterMetric.Metric[0].Label, "service"))
				assert.Equal(t, "410", getLabel(counterMetric.Metric[0].Label, "http_code"))
				require.Equal(t, 1.0, counterMetric.Metric[0].Counter.GetValue())
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			registry := prometheus.NewRegistry()

			app := fiber.New()
			app.Use(New(
				WithRegisterer(registry),
				WithNamespace("foo"),
				WithSubsystem("bar"),
				WithLabel("baz", "zab"),
				WithServiceName("foobar"),
				WithOperationFilter(func(ctx *fiber.Ctx) bool { return ctx.Path() == "/filtered" }),
			))

			app.Get("test", func(ctx *fiber.Ctx) error { return nil })
			app.Get("filtered", func(ctx *fiber.Ctx) error { return nil })
			app.Post("test", func(ctx *fiber.Ctx) error { return ctx.SendStatus(500) })
			app.Patch("error", func(ctx *fiber.Ctx) error { return fiber.ErrGone })

			defer app.Shutdown() // nolint: errcheck

			// WHEN
			resp, err := app.Test(tc.req, -1)
			require.NoError(t, err)

			defer resp.Body.Close()

			metrics, err := registry.Gather()
			require.NoError(t, err)

			// THEN
			tc.assert(t, metrics)
		})
	}
}
