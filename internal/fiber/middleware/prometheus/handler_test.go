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

func containsLabel(labels []*dto.LabelPair, name, value string) bool {
	for _, label := range labels {
		if label.GetName() == name && label.GetValue() == value {
			return true
		}
	}

	return false
}

func TestHandlerNew(t *testing.T) {
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
				assert.Equal(t, "Duration of all HTTP requests by status code, method and path.",
					histMetric.GetHelp())

				require.Len(t, histMetric.Metric, 1)
				assert.Truef(t, containsLabel(histMetric.Metric[0].Label, "baz", "zab"),
					"missing baz=zab label")
				assert.Truef(t, containsLabel(histMetric.Metric[0].Label, "method", "GET"),
					"missing method=GET label")
				assert.Truef(t, containsLabel(histMetric.Metric[0].Label, "path", "/test"),
					"missing path=/test label")
				assert.Truef(t, containsLabel(histMetric.Metric[0].Label, "service", "foobar"),
					"missing service=foobar label")
				assert.Truef(t, containsLabel(histMetric.Metric[0].Label, "status_code", "200"),
					"missing status_code=200 label")

				require.Len(t, histMetric.Metric[0].Histogram.Bucket, 22)

				gaugeMetric := metricForType(metrics, dto.MetricType_GAUGE.Enum())
				assert.Equal(t, "foo_bar_requests_in_progress_total", gaugeMetric.GetName())
				assert.Equal(t, "All the requests in progress", gaugeMetric.GetHelp())

				require.Len(t, gaugeMetric.Metric, 1)
				assert.Truef(t, containsLabel(gaugeMetric.Metric[0].Label, "baz", "zab"),
					"missing baz=zab label")
				assert.Truef(t, containsLabel(gaugeMetric.Metric[0].Label, "method", "GET"),
					"missing method=GET label")
				assert.Truef(t, containsLabel(gaugeMetric.Metric[0].Label, "service", "foobar"),
					"missing service=foobar label")

				require.Equal(t, 0.0, gaugeMetric.Metric[0].Gauge.GetValue())

				counterMetric := metricForType(metrics, dto.MetricType_COUNTER.Enum())
				assert.Equal(t, "foo_bar_requests_total", counterMetric.GetName())
				assert.Equal(t, "Count all http requests by status code, method and path.", counterMetric.GetHelp())

				require.Len(t, counterMetric.Metric, 1)
				assert.Truef(t, containsLabel(counterMetric.Metric[0].Label, "baz", "zab"),
					"missing baz=zab label")
				assert.Truef(t, containsLabel(counterMetric.Metric[0].Label, "method", "GET"),
					"missing method=GET label")
				assert.Truef(t, containsLabel(counterMetric.Metric[0].Label, "path", "/test"),
					"missing path=/test label")
				assert.Truef(t, containsLabel(counterMetric.Metric[0].Label, "service", "foobar"),
					"missing service=foobar label")
				assert.Truef(t, containsLabel(counterMetric.Metric[0].Label, "status_code", "200"),
					"missing status_code=200 label")

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
				assert.Equal(t, "Duration of all HTTP requests by status code, method and path.",
					histMetric.GetHelp())

				require.Len(t, histMetric.Metric, 1)
				assert.Truef(t, containsLabel(histMetric.Metric[0].Label, "baz", "zab"),
					"missing baz=zab label")
				assert.Truef(t, containsLabel(histMetric.Metric[0].Label, "method", "POST"),
					"missing method=GET label")
				assert.Truef(t, containsLabel(histMetric.Metric[0].Label, "path", "/test"),
					"missing path=/test label")
				assert.Truef(t, containsLabel(histMetric.Metric[0].Label, "service", "foobar"),
					"missing service=foobar label")
				assert.Truef(t, containsLabel(histMetric.Metric[0].Label, "status_code", "500"),
					"missing status_code=500 label")

				require.Len(t, histMetric.Metric[0].Histogram.Bucket, 22)

				gaugeMetric := metricForType(metrics, dto.MetricType_GAUGE.Enum())
				assert.Equal(t, "foo_bar_requests_in_progress_total", gaugeMetric.GetName())
				assert.Equal(t, "All the requests in progress", gaugeMetric.GetHelp())

				require.Len(t, gaugeMetric.Metric, 1)
				assert.Truef(t, containsLabel(gaugeMetric.Metric[0].Label, "baz", "zab"),
					"missing baz=zab label")
				assert.Truef(t, containsLabel(gaugeMetric.Metric[0].Label, "method", "POST"),
					"missing method=GET label")
				assert.Truef(t, containsLabel(gaugeMetric.Metric[0].Label, "service", "foobar"),
					"missing service=foobar label")

				require.Equal(t, 0.0, gaugeMetric.Metric[0].Gauge.GetValue())

				counterMetric := metricForType(metrics, dto.MetricType_COUNTER.Enum())
				assert.Equal(t, "foo_bar_requests_total", counterMetric.GetName())
				assert.Equal(t, "Count all http requests by status code, method and path.", counterMetric.GetHelp())

				require.Len(t, counterMetric.Metric, 1)
				assert.Truef(t, containsLabel(counterMetric.Metric[0].Label, "baz", "zab"),
					"missing baz=zab label")
				assert.Truef(t, containsLabel(counterMetric.Metric[0].Label, "method", "POST"),
					"missing method=GET label")
				assert.Truef(t, containsLabel(counterMetric.Metric[0].Label, "path", "/test"),
					"missing path=/test label")
				assert.Truef(t, containsLabel(counterMetric.Metric[0].Label, "service", "foobar"),
					"missing service=foobar label")
				assert.Truef(t, containsLabel(counterMetric.Metric[0].Label, "status_code", "500"),
					"missing status_code=500 label")

				require.Equal(t, 1.0, counterMetric.Metric[0].Counter.GetValue())
			},
		},
		{
			uc:  "metrics for request which server raising an error",
			req: httptest.NewRequest(http.MethodPatch, "/error", nil),
			assert: func(t *testing.T, metrics []*dto.MetricFamily) {
				t.Helper()

				assert.Len(t, metrics, 3)

				histMetric := metricForType(metrics, dto.MetricType_HISTOGRAM.Enum())
				assert.Equal(t, "foo_bar_request_duration_seconds", histMetric.GetName())
				assert.Equal(t, "Duration of all HTTP requests by status code, method and path.",
					histMetric.GetHelp())

				require.Len(t, histMetric.Metric, 1)
				assert.Truef(t, containsLabel(histMetric.Metric[0].Label, "baz", "zab"),
					"missing baz=zab label")
				assert.Truef(t, containsLabel(histMetric.Metric[0].Label, "method", "PATCH"),
					"missing method=PATCH label")
				assert.Truef(t, containsLabel(histMetric.Metric[0].Label, "path", "/error"),
					"missing path=/error label")
				assert.Truef(t, containsLabel(histMetric.Metric[0].Label, "service", "foobar"),
					"missing service=foobar label")
				assert.Truef(t, containsLabel(histMetric.Metric[0].Label, "status_code", "410"),
					"missing status_code=410 label")

				require.Len(t, histMetric.Metric[0].Histogram.Bucket, 22)

				gaugeMetric := metricForType(metrics, dto.MetricType_GAUGE.Enum())
				assert.Equal(t, "foo_bar_requests_in_progress_total", gaugeMetric.GetName())
				assert.Equal(t, "All the requests in progress", gaugeMetric.GetHelp())

				require.Len(t, gaugeMetric.Metric, 1)
				assert.Truef(t, containsLabel(gaugeMetric.Metric[0].Label, "baz", "zab"),
					"missing baz=zab label")
				assert.Truef(t, containsLabel(gaugeMetric.Metric[0].Label, "method", "PATCH"),
					"missing method=PATCH label")
				assert.Truef(t, containsLabel(gaugeMetric.Metric[0].Label, "service", "foobar"),
					"missing service=foobar label")

				require.Equal(t, 0.0, gaugeMetric.Metric[0].Gauge.GetValue())

				counterMetric := metricForType(metrics, dto.MetricType_COUNTER.Enum())
				assert.Equal(t, "foo_bar_requests_total", counterMetric.GetName())
				assert.Equal(t, "Count all http requests by status code, method and path.", counterMetric.GetHelp())

				require.Len(t, counterMetric.Metric, 1)
				assert.Truef(t, containsLabel(counterMetric.Metric[0].Label, "baz", "zab"),
					"missing baz=zab label")
				assert.Truef(t, containsLabel(counterMetric.Metric[0].Label, "method", "PATCH"),
					"missing method=PATCH label")
				assert.Truef(t, containsLabel(counterMetric.Metric[0].Label, "path", "/error"),
					"missing path=/error label")
				assert.Truef(t, containsLabel(counterMetric.Metric[0].Label, "service", "foobar"),
					"missing service=foobar label")
				assert.Truef(t, containsLabel(counterMetric.Metric[0].Label, "status_code", "410"),
					"missing status_code=410 label")

				require.Equal(t, 1.0, counterMetric.Metric[0].Counter.GetValue())
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
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

			resp, err := app.Test(tc.req, -1)
			require.NoError(t, err)

			defer resp.Body.Close()

			metrics, err := registry.Gather()
			require.NoError(t, err)

			tc.assert(t, metrics)
		})
	}
}
