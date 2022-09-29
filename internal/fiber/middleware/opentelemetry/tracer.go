package opentelemetry

import (
	"errors"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp/fasthttpadaptor"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.12.0"
	"go.opentelemetry.io/otel/trace"
)

var ErrNoParentSpan = errors.New("no parent span available")

type tracer struct {
	c *tracerConfig
}

type tracerConfig struct {
	tracer                 trace.Tracer
	propagator             propagation.TextMapPropagator
	spanObserver           SpanObserver
	operationName          OperationNameProvider
	filterOperation        OperationFilter
	skipSpansWithoutParent bool
}

func newTracerConfig(opts ...Option) *tracerConfig {
	options := defaultOptions

	for _, opt := range opts {
		opt(&options)
	}

	return &tracerConfig{
		tracer:                 options.tracer,
		propagator:             propagation.NewCompositeTextMapPropagator(options.propagators...),
		spanObserver:           options.spanObserver,
		operationName:          options.operationName,
		filterOperation:        options.filterOperation,
		skipSpansWithoutParent: options.skipSpansWithoutParent,
	}
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

func (t *tracer) startSpan(ctx *fiber.Ctx, time time.Time) (trace.Span, error) {
	req := &http.Request{}

	err := fasthttpadaptor.ConvertRequest(ctx.Context(), req, true)
	if err != nil {
		return nil, err
	}

	spanCtx := t.c.propagator.Extract(ctx.UserContext(), propagation.HeaderCarrier(req.Header))

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
	trc := &tracer{c: newTracerConfig(opts...)}

	return trc.manageSpans
}
