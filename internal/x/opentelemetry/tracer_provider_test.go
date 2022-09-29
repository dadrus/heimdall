package opentelemetry

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dadrus/heimdall/internal/x/opentelemetry/propagators"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

func TestOpenTelemetry(t *testing.T) {
	provider, err := NewTracerProvider("foo-service", "1.1.1")
	assert.NoError(t, err)

	defer provider.Shutdown(context.Background())

	propagator := propagators.New()

	// Register our TracerProvider as the global so any imported
	// instrumentation in the future will default to using it.
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagator)
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) { log.Logger.Error().Err(err).Msg("OTEL Error") }))

	parentSpanContext := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID{1},
		SpanID:     trace.SpanID{2},
		TraceFlags: trace.FlagsSampled,
	})
	ctx := trace.ContextWithRemoteSpanContext(context.Background(), parentSpanContext)

	var parentSpan trace.Span

	content := []byte("Hello, world!")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := propagation.TraceContext{}.Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		span := trace.SpanContextFromContext(ctx)
		assert.Equal(t, parentSpan.SpanContext().TraceID(), span.TraceID())

		_, err := w.Write(content)
		require.NoError(t, err)
	}))
	defer ts.Close()

	app := fiber.New()
	app.Use(opentelemetry.New(opentelemetry.WithTracer(provider.Tracer("foo"))))
	app.Get("test", func(ctx *fiber.Ctx) error {
		parentSpan = trace.SpanFromContext(ctx.UserContext())

		c := http.Client{Transport: otelhttp.NewTransport(http.DefaultTransport)}
		req, err := http.NewRequestWithContext(ctx.UserContext(), http.MethodGet, ts.URL, nil)
		require.NoError(t, err)

		res, err := c.Do(req)
		require.NoError(t, err)

		defer res.Body.Close()

		body, err := io.ReadAll(res.Body)
		require.NoError(t, err)

		require.Equal(t, content, body)

		return nil
	})
	defer app.Shutdown()

	req := httptest.NewRequest(http.MethodGet, "/test", nil).WithContext(ctx)
	propagation.TraceContext{}.Inject(ctx, propagation.HeaderCarrier(req.Header))

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	resp.Body.Close()
}
