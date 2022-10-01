package opentelemetry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/dadrus/heimdall/internal/x/opentelemetry/mocks"
)

func TestTracerSpanManagementWithoutSkippingOnMissingParentSpan(t *testing.T) {
	t.Parallel()

	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	mtracer := mocks.NewMockTracer()
	parentSpanContext := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID{1},
		SpanID:     trace.SpanID{2},
		TraceFlags: trace.FlagsSampled,
	})
	ctx := trace.ContextWithRemoteSpanContext(context.Background(), parentSpanContext)

	app := fiber.New()
	app.Use(New(
		WithTracer(mtracer),
		WithOperationFilter(func(ctx *fiber.Ctx) bool { return ctx.Path() == "/filtered" }),
		WithSpanObserver(func(ctx *fiber.Ctx, span trace.Span) {
			if ctx.Method() == fiber.MethodGet {
				span.SetAttributes(attribute.KeyValue{Key: "foo", Value: attribute.StringValue("bar")})
			}
		})))

	app.Get("test", func(ctx *fiber.Ctx) error { return nil })
	app.Get("filtered", func(ctx *fiber.Ctx) error { return nil })
	app.Post("test", func(ctx *fiber.Ctx) error { return ctx.SendStatus(500) })

	defer app.Shutdown() // nolint: errcheck

	for _, tc := range []struct {
		uc      string
		request *http.Request
		assert  func(t *testing.T, mtracer *mocks.MockTracer)
	}{
		{
			uc:      "request without parent span, resulting in http 200",
			request: httptest.NewRequest(http.MethodGet, "/test", nil),
			assert: func(t *testing.T, mtracer *mocks.MockTracer) {
				t.Helper()

				spans := mtracer.FinishedSpans
				require.Len(t, spans, 1)
				assert.NotEqual(t, parentSpanContext.SpanID(), spans[0].SpanContext().SpanID())
				assert.NotEqual(t, parentSpanContext.TraceID(), spans[0].SpanContext().TraceID())

				assert.Equal(t, "HTTP GET URL: /test", spans[0].Name)
				assert.Equal(t, trace.SpanKindServer, spans[0].SpanKind)

				attributes := spans[0].Attributes
				assert.Len(t, attributes, 12)
				assert.Contains(t, attributes, attribute.String("net.transport", "ip_tcp"))
				assert.Contains(t, attributes, attribute.String("net.peer.ip", "0.0.0.0"))
				assert.Contains(t, attributes, attribute.String("net.host.name", "example.com"))
				assert.Contains(t, attributes, attribute.String("http.target", "/test"))
				assert.Contains(t, attributes, attribute.String("http.scheme", "http"))
				assert.Contains(t, attributes, attribute.String("http.host", "example.com"))
				assert.Contains(t, attributes, attribute.String("http.flavor", "1.1"))
				assert.Contains(t, attributes, attribute.String("http.method", "GET"))
				assert.Contains(t, attributes, attribute.String("foo", "bar"))
				assert.Contains(t, attributes, attribute.Int64("http.status_code", 200))
				assert.Contains(t, attributes, attribute.Int64("status.code", 0))
				assert.Contains(t, attributes, attribute.String("status.message", ""))
			},
		},
		{
			uc:      "request without parent span, resulting in http 500",
			request: httptest.NewRequest(http.MethodPost, "/test", nil),
			assert: func(t *testing.T, mtracer *mocks.MockTracer) {
				t.Helper()

				spans := mtracer.FinishedSpans
				require.Len(t, spans, 1)
				assert.NotEqual(t, parentSpanContext.SpanID(), spans[0].SpanContext().SpanID())
				assert.NotEqual(t, parentSpanContext.TraceID(), spans[0].SpanContext().TraceID())

				assert.Equal(t, "HTTP POST URL: /test", spans[0].Name)
				assert.Equal(t, trace.SpanKindServer, spans[0].SpanKind)

				attributes := spans[0].Attributes
				assert.Len(t, attributes, 11)
				assert.Contains(t, attributes, attribute.String("net.transport", "ip_tcp"))
				assert.Contains(t, attributes, attribute.String("net.peer.ip", "0.0.0.0"))
				assert.Contains(t, attributes, attribute.String("net.host.name", "example.com"))
				assert.Contains(t, attributes, attribute.String("http.target", "/test"))
				assert.Contains(t, attributes, attribute.String("http.scheme", "http"))
				assert.Contains(t, attributes, attribute.String("http.host", "example.com"))
				assert.Contains(t, attributes, attribute.String("http.flavor", "1.1"))
				assert.Contains(t, attributes, attribute.String("http.method", "POST"))
				assert.Contains(t, attributes, attribute.Int64("http.status_code", 500))
				assert.Contains(t, attributes, attribute.Int64("status.code", 1))
				assert.Contains(t, attributes, attribute.String("status.message", ""))
			},
		},
		{
			uc: "request with parent span, resulting in http 200",
			request: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/test", nil)
				propagation.TraceContext{}.Inject(ctx, propagation.HeaderCarrier(req.Header))

				return req
			}(),
			assert: func(t *testing.T, mtracer *mocks.MockTracer) {
				t.Helper()

				spans := mtracer.FinishedSpans
				require.Len(t, spans, 1)
				assert.Equal(t, parentSpanContext.SpanID(), spans[0].ParentSpanID)
				assert.Equal(t, parentSpanContext.TraceID(), spans[0].SpanContext().TraceID())

				assert.Equal(t, "HTTP GET URL: /test", spans[0].Name)
				assert.Equal(t, trace.SpanKindServer, spans[0].SpanKind)

				attributes := spans[0].Attributes
				assert.Len(t, attributes, 12)
				assert.Contains(t, attributes, attribute.String("net.transport", "ip_tcp"))
				assert.Contains(t, attributes, attribute.String("net.peer.ip", "0.0.0.0"))
				assert.Contains(t, attributes, attribute.String("net.host.name", "example.com"))
				assert.Contains(t, attributes, attribute.String("http.target", "/test"))
				assert.Contains(t, attributes, attribute.String("http.scheme", "http"))
				assert.Contains(t, attributes, attribute.String("http.host", "example.com"))
				assert.Contains(t, attributes, attribute.String("http.flavor", "1.1"))
				assert.Contains(t, attributes, attribute.String("http.method", "GET"))
				assert.Contains(t, attributes, attribute.String("foo", "bar"))
				assert.Contains(t, attributes, attribute.Int64("http.status_code", 200))
				assert.Contains(t, attributes, attribute.Int64("status.code", 0))
				assert.Contains(t, attributes, attribute.String("status.message", ""))
			},
		},
		{
			uc:      "filtered request",
			request: httptest.NewRequest(http.MethodGet, "/filtered", nil),
			assert: func(t *testing.T, mtracer *mocks.MockTracer) {
				t.Helper()

				require.Len(t, mtracer.FinishedSpans, 0)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			mtracer.Reset()

			// WHEN
			resp, err := app.Test(tc.request, -1)
			require.NoError(t, err)
			resp.Body.Close()

			// THEN
			tc.assert(t, mtracer)
		})
	}
}

func TestTracerSpanManagementWithSkippingOnMissingParentSpan(t *testing.T) {
	t.Parallel()

	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	mtracer := mocks.NewMockTracer()
	parentSpanContext := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{1},
		SpanID:  trace.SpanID{2},
		Remote:  true,
	})
	ctx := trace.ContextWithRemoteSpanContext(context.Background(), parentSpanContext)

	app := fiber.New()
	app.Use(New(
		WithTracer(mtracer),
		WithSkipSpanWithoutParent(true)))

	app.Get("test", func(ctx *fiber.Ctx) error { return nil })
	// nolint: errcheck
	defer app.Shutdown()

	for _, tc := range []struct {
		uc      string
		request *http.Request
		assert  func(t *testing.T, mtracer *mocks.MockTracer)
	}{
		{
			uc:      "request without parent span",
			request: httptest.NewRequest(http.MethodGet, "/test", nil),
			assert: func(t *testing.T, mtracer *mocks.MockTracer) {
				t.Helper()

				require.Len(t, mtracer.FinishedSpans, 0)
			},
		},
		{
			uc: "request with parent span",
			request: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/test", nil)
				propagation.TraceContext{}.Inject(ctx, propagation.HeaderCarrier(req.Header))

				return req
			}(),
			assert: func(t *testing.T, mtracer *mocks.MockTracer) {
				t.Helper()

				spans := mtracer.FinishedSpans
				require.Len(t, spans, 1)
				assert.Equal(t, parentSpanContext.SpanID(), spans[0].ParentSpanID)
				assert.Equal(t, parentSpanContext.TraceID(), spans[0].SpanContext().TraceID())

				assert.Equal(t, "HTTP GET URL: /test", spans[0].Name)
				assert.Equal(t, trace.SpanKindServer, spans[0].SpanKind)

				attributes := spans[0].Attributes
				assert.Len(t, attributes, 11)
				assert.Contains(t, attributes, attribute.String("net.transport", "ip_tcp"))
				assert.Contains(t, attributes, attribute.String("net.peer.ip", "0.0.0.0"))
				assert.Contains(t, attributes, attribute.String("net.host.name", "example.com"))
				assert.Contains(t, attributes, attribute.String("http.target", "/test"))
				assert.Contains(t, attributes, attribute.String("http.scheme", "http"))
				assert.Contains(t, attributes, attribute.String("http.host", "example.com"))
				assert.Contains(t, attributes, attribute.String("http.flavor", "1.1"))
				assert.Contains(t, attributes, attribute.String("http.method", "GET"))
				assert.Contains(t, attributes, attribute.Int64("http.status_code", 200))
				assert.Contains(t, attributes, attribute.Int64("status.code", 0))
				assert.Contains(t, attributes, attribute.String("status.message", ""))
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			mtracer.Reset()

			// WHEN
			resp, err := app.Test(tc.request, -1)
			require.NoError(t, err)
			resp.Body.Close()

			// THEN
			tc.assert(t, mtracer)
		})
	}
}

func TestSpanIsSetToContextToEnablePropagationToUpstreamServices(t *testing.T) {
	t.Parallel()

	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	// GIVEN
	app := fiber.New()
	app.Use(New(WithTracer(mocks.NewMockTracer())))

	var ctx context.Context

	app.Get("test", func(fiberCtx *fiber.Ctx) error {
		ctx = fiberCtx.UserContext()

		return nil
	})
	// nolint: errcheck
	defer app.Shutdown()

	// WHEN
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/test", nil), -1)

	// THEN
	require.NoError(t, err)
	resp.Body.Close()

	span := trace.SpanFromContext(ctx)
	require.NotNil(t, span)

	impl, ok := span.(*mocks.MockSpan)
	require.True(t, ok)

	assert.Equal(t, "HTTP GET URL: /test", impl.Name)
	assert.Equal(t, trace.SpanKindServer, impl.SpanKind)

	attributes := impl.Attributes
	assert.Len(t, attributes, 11)
	assert.Contains(t, attributes, attribute.String("net.transport", "ip_tcp"))
	assert.Contains(t, attributes, attribute.String("net.peer.ip", "0.0.0.0"))
	assert.Contains(t, attributes, attribute.String("net.host.name", "example.com"))
	assert.Contains(t, attributes, attribute.String("http.target", "/test"))
	assert.Contains(t, attributes, attribute.String("http.scheme", "http"))
	assert.Contains(t, attributes, attribute.String("http.host", "example.com"))
	assert.Contains(t, attributes, attribute.String("http.flavor", "1.1"))
	assert.Contains(t, attributes, attribute.String("http.method", "GET"))
	assert.Contains(t, attributes, attribute.Int64("http.status_code", 200))
	assert.Contains(t, attributes, attribute.Int64("status.code", 0))
	assert.Contains(t, attributes, attribute.String("status.message", ""))
}
