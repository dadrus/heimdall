package tracing

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"
	"github.com/opentracing/opentracing-go/mocktracer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTracerSpanManagementWithoutSkippingOnMissingParentSpan(t *testing.T) {
	t.Parallel()

	mtracer := mocktracer.New()

	parentSpanContext := mocktracer.MockSpanContext{TraceID: 100, SpanID: 200, Sampled: true}
	carrier := opentracing.HTTPHeadersCarrier(make(map[string][]string))
	err := mtracer.Inject(parentSpanContext, opentracing.HTTPHeaders, carrier)
	require.NoError(t, err)

	app := fiber.New()
	app.Use(New(
		WithTracer(mtracer),
		WithOperationFilter(func(ctx *fiber.Ctx) bool { return ctx.Path() == "/filtered" }),
		WithSpanObserver(func(span opentracing.Span, ctx *fiber.Ctx) {
			if ctx.Method() == fiber.MethodGet {
				span.SetTag("foo", "bar")
			}
		})))

	app.Get("test", func(ctx *fiber.Ctx) error { return nil })
	app.Get("filtered", func(ctx *fiber.Ctx) error { return nil })
	app.Post("test", func(ctx *fiber.Ctx) error { return ctx.SendStatus(500) })
	// nolint: errcheck
	defer app.Shutdown()

	setParentContextHeader := func(req *http.Request) {
		for name, valueList := range carrier {
			for _, value := range valueList {
				req.Header.Add(name, value)
			}
		}
	}

	for _, tc := range []struct {
		uc      string
		request *http.Request
		assert  func(t *testing.T, mtracer *mocktracer.MockTracer)
	}{
		{
			uc:      "request without parent span, resulting in http 200",
			request: httptest.NewRequest(http.MethodGet, "/test", nil),
			assert: func(t *testing.T, mtracer *mocktracer.MockTracer) {
				t.Helper()

				spans := mtracer.FinishedSpans()
				require.Len(t, spans, 1)
				assert.NotEqual(t, parentSpanContext.SpanID, spans[0].ParentID)
				assert.NotEqual(t, parentSpanContext.TraceID, spans[0].SpanContext.TraceID)

				assert.Equal(t, "HTTP GET URL: /test", spans[0].OperationName)

				tags := spans[0].Tags()
				assert.Len(t, tags, 6)
				assert.Equal(t, ext.SpanKindRPCServerEnum, tags[string(ext.SpanKind)])
				assert.Equal(t, http.MethodGet, tags[string(ext.HTTPMethod)])
				assert.Equal(t, "/test", tags[string(ext.HTTPUrl)])
				assert.Equal(t, uint16(200), tags[string(ext.HTTPStatusCode)])
				assert.Equal(t, "0.0.0.0", tags[string(ext.PeerAddress)])
				assert.Equal(t, "bar", tags["foo"])
			},
		},
		{
			uc:      "request without parent span, resulting in http 500",
			request: httptest.NewRequest(http.MethodPost, "/test", nil),
			assert: func(t *testing.T, mtracer *mocktracer.MockTracer) {
				t.Helper()

				spans := mtracer.FinishedSpans()
				require.Len(t, spans, 1)
				assert.NotEqual(t, parentSpanContext.SpanID, spans[0].ParentID)
				assert.NotEqual(t, parentSpanContext.TraceID, spans[0].SpanContext.TraceID)

				assert.Equal(t, "HTTP POST URL: /test", spans[0].OperationName)

				tags := spans[0].Tags()
				assert.Len(t, tags, 6)
				assert.Equal(t, ext.SpanKindRPCServerEnum, tags[string(ext.SpanKind)])
				assert.Equal(t, http.MethodPost, tags[string(ext.HTTPMethod)])
				assert.Equal(t, "/test", tags[string(ext.HTTPUrl)])
				assert.Equal(t, uint16(500), tags[string(ext.HTTPStatusCode)])
				assert.Equal(t, "0.0.0.0", tags[string(ext.PeerAddress)])
				assert.Equal(t, true, tags[string(ext.Error)])
			},
		},
		{
			uc: "request with parent span, resulting in http 200",
			request: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/test", nil)
				setParentContextHeader(req)

				return req
			}(),
			assert: func(t *testing.T, mtracer *mocktracer.MockTracer) {
				t.Helper()

				spans := mtracer.FinishedSpans()
				require.Len(t, spans, 1)
				assert.Equal(t, parentSpanContext.SpanID, spans[0].ParentID)
				assert.Equal(t, parentSpanContext.TraceID, spans[0].SpanContext.TraceID)

				assert.Equal(t, "HTTP GET URL: /test", spans[0].OperationName)

				tags := spans[0].Tags()
				assert.Len(t, tags, 6)
				assert.Equal(t, ext.SpanKindRPCServerEnum, tags[string(ext.SpanKind)])
				assert.Equal(t, http.MethodGet, tags[string(ext.HTTPMethod)])
				assert.Equal(t, "/test", tags[string(ext.HTTPUrl)])
				assert.Equal(t, uint16(200), tags[string(ext.HTTPStatusCode)])
				assert.Equal(t, "0.0.0.0", tags[string(ext.PeerAddress)])
				assert.Equal(t, "bar", tags["foo"])
			},
		},
		{
			uc:      "filtered request",
			request: httptest.NewRequest(http.MethodGet, "/filtered", nil),
			assert: func(t *testing.T, mtracer *mocktracer.MockTracer) {
				t.Helper()

				spans := mtracer.FinishedSpans()
				require.Len(t, spans, 0)
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

	mtracer := mocktracer.New()

	parentSpanContext := mocktracer.MockSpanContext{TraceID: 100, SpanID: 200, Sampled: true}
	carrier := opentracing.HTTPHeadersCarrier(make(map[string][]string))
	err := mtracer.Inject(parentSpanContext, opentracing.HTTPHeaders, carrier)
	require.NoError(t, err)

	app := fiber.New()
	app.Use(New(
		WithTracer(mtracer),
		WithSkipSpanWithoutParent(true)))

	app.Get("test", func(ctx *fiber.Ctx) error { return nil })
	// nolint: errcheck
	defer app.Shutdown()

	setParentContextHeader := func(req *http.Request) {
		for name, valueList := range carrier {
			for _, value := range valueList {
				req.Header.Add(name, value)
			}
		}
	}

	for _, tc := range []struct {
		uc      string
		request *http.Request
		assert  func(t *testing.T, mtracer *mocktracer.MockTracer)
	}{
		{
			uc:      "request without parent span",
			request: httptest.NewRequest(http.MethodGet, "/test", nil),
			assert: func(t *testing.T, mtracer *mocktracer.MockTracer) {
				t.Helper()

				spans := mtracer.FinishedSpans()
				require.Len(t, spans, 0)
			},
		},
		{
			uc: "request with parent span",
			request: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/test", nil)
				setParentContextHeader(req)

				return req
			}(),
			assert: func(t *testing.T, mtracer *mocktracer.MockTracer) {
				t.Helper()

				spans := mtracer.FinishedSpans()
				require.Len(t, spans, 1)
				assert.Equal(t, parentSpanContext.SpanID, spans[0].ParentID)
				assert.Equal(t, parentSpanContext.TraceID, spans[0].SpanContext.TraceID)

				assert.Equal(t, "HTTP GET URL: /test", spans[0].OperationName)

				tags := spans[0].Tags()
				assert.Len(t, tags, 5)
				assert.Equal(t, ext.SpanKindRPCServerEnum, tags[string(ext.SpanKind)])
				assert.Equal(t, http.MethodGet, tags[string(ext.HTTPMethod)])
				assert.Equal(t, "/test", tags[string(ext.HTTPUrl)])
				assert.Equal(t, uint16(200), tags[string(ext.HTTPStatusCode)])
				assert.Equal(t, "0.0.0.0", tags[string(ext.PeerAddress)])
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

	// GIVEN
	app := fiber.New()
	app.Use(New(WithTracer(mocktracer.New())))

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

	span := opentracing.SpanFromContext(ctx)
	require.NotNil(t, span)

	impl, ok := span.(*mocktracer.MockSpan)
	require.True(t, ok)

	assert.Equal(t, "HTTP GET URL: /test", impl.OperationName)

	tags := impl.Tags()
	assert.Len(t, tags, 5)
	assert.Equal(t, ext.SpanKindRPCServerEnum, tags[string(ext.SpanKind)])
	assert.Equal(t, http.MethodGet, tags[string(ext.HTTPMethod)])
	assert.Equal(t, "/test", tags[string(ext.HTTPUrl)])
	assert.Equal(t, uint16(200), tags[string(ext.HTTPStatusCode)])
	assert.Equal(t, "0.0.0.0", tags[string(ext.PeerAddress)])
}
