package tracing

import (
	"github.com/gofiber/fiber/v2"
	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"
)

type tracer struct {
	c opts
}

func (t *tracer) manageSpans(ctx *fiber.Ctx) error {
	if t.c.filterOperation(ctx) {
		return ctx.Next()
	}

	span, err := t.startSpan(ctx)
	if err != nil {
		return ctx.Next()
	}

	defer t.endSpan(ctx, span)

	return ctx.Next()
}

func (t *tracer) spanContext(ctx *fiber.Ctx) (opentracing.SpanContext, error) {
	headers := make(opentracing.HTTPHeadersCarrier)

	ctx.Request().Header.VisitAll(func(key, value []byte) {
		headers.Set(string(key), string(value))
	})

	return t.c.tracer.Extract(opentracing.HTTPHeaders, headers)
}

func (t *tracer) startSpan(ctx *fiber.Ctx) (opentracing.Span, error) {
	sc, err := t.spanContext(ctx)

	var span opentracing.Span

	if err == nil {
		span = t.c.tracer.StartSpan(t.c.operationName(ctx), ext.RPCServerOption(sc))
	} else if !t.c.skipSpansWithoutParent {
		span = t.c.tracer.StartSpan(t.c.operationName(ctx), ext.RPCServerOption(nil))
		err = nil
	}

	if span != nil {
		ext.SpanKindRPCServer.Set(span)
		ext.HTTPMethod.Set(span, ctx.Method())
		ext.HTTPUrl.Set(span, ctx.OriginalURL())
		ext.PeerAddress.Set(span, ctx.IP())

		t.c.spanObserver(span, ctx)

		ctx.SetUserContext(opentracing.ContextWithSpan(ctx.UserContext(), span))
	}

	return span, err
}

func (t *tracer) endSpan(ctx *fiber.Ctx, span opentracing.Span) {
	status := ctx.Response().StatusCode()
	ext.HTTPStatusCode.Set(span, uint16(status))

	if status >= fiber.StatusInternalServerError {
		ext.Error.Set(span, true)
	}

	span.Finish()
}

func New(opts ...Option) fiber.Handler {
	// nolint: varnamelen
	t := &tracer{c: defaultOptions}

	for _, opt := range opts {
		opt(&t.c)
	}

	return t.manageSpans
}
