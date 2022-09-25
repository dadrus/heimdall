package opentel

import (
	"errors"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp/fasthttpadaptor"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.12.0"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/net/context"
)

var ErrNoParentSpan = errors.New("no parent span available")

type tracer struct {
	c opts
}

func (t *tracer) manageSpans(ctx *fiber.Ctx) error {
	now := time.Now()

	if t.c.filterOperation(ctx) {
		return ctx.Next()
	}

	span, err := t.startSpan(ctx, now)
	if err != nil {
		return ctx.Next()
	}

	defer t.endSpan(ctx, span)

	return ctx.Next()
}

func (t *tracer) spanContext(ctx *fiber.Ctx, req *http.Request) context.Context {
	propagator := propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)

	return propagator.Extract(ctx.UserContext(), propagation.HeaderCarrier(req.Header))
}

func (t *tracer) startSpan(ctx *fiber.Ctx, time time.Time) (trace.Span, error) {
	req := &http.Request{}

	err := fasthttpadaptor.ConvertRequest(ctx.Context(), req, true)
	if err != nil {
		return nil, err
	}

	spanCtx := t.spanContext(ctx, req)

	var spanOpts []trace.SpanStartOption

	sc := trace.SpanContextFromContext(spanCtx)
	if !sc.IsValid() {
		if t.c.skipSpansWithoutParent {
			return nil, ErrNoParentSpan
		}

		spanOpts = append(spanOpts, trace.WithNewRoot())
	}

	spanOpts = append(spanOpts,
		trace.WithAttributes(semconv.NetAttributesFromHTTPRequest("tcp", req)...),
		trace.WithAttributes(semconv.EndUserAttributesFromHTTPRequest(req)...),
		trace.WithAttributes(semconv.HTTPServerAttributesFromHTTPRequest("", "", req)...),
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithTimestamp(time))

	userCtx, span := t.c.tracer.Start(spanCtx, t.c.operationName(ctx), spanOpts...)

	t.c.spanObserver(ctx, span)

	ctx.SetUserContext(userCtx)

	return span, nil
}

func (t *tracer) endSpan(ctx *fiber.Ctx, span trace.Span) {
	statusCode := ctx.Response().StatusCode()
	attributes := semconv.HTTPAttributesFromHTTPStatusCode(statusCode)

	span.SetAttributes(attributes...)
	span.SetStatus(semconv.SpanStatusFromHTTPStatusCode(statusCode))

	span.End(trace.WithTimestamp(time.Now()), trace.WithStackTrace(false))
}

func New(opts ...Option) fiber.Handler {
	trc := &tracer{c: defaultOptions}

	for _, opt := range opts {
		opt(&trc.c)
	}

	return trc.manageSpans
}
