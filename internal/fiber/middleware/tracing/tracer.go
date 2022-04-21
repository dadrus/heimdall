package tracing

import (
	"github.com/gofiber/fiber/v2"
	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"
)

func New(opts ...Option) fiber.Handler {
	config := defaultOptions

	for _, opt := range opts {
		opt(&config)
	}

	return func(ctx *fiber.Ctx) error {
		if config.filterOperation != nil && config.filterOperation(ctx) {
			return ctx.Next()
		}

		span, err := startSpan(ctx, config)
		if err != nil {
			return ctx.Next()
		}

		defer endSpan(ctx, span)

		return ctx.Next()
	}
}

func startSpan(ctx *fiber.Ctx, config opts) (opentracing.Span, error) {
	sc, err := spanContext(ctx, config)

	var span opentracing.Span

	if err == nil {
		span = config.tracer.StartSpan(config.operationName(ctx), opentracing.ChildOf(sc))
	} else if !config.skipSpansWithoutParent {
		span = config.tracer.StartSpan(config.operationName(ctx))
	}

	if span != nil {
		ext.SpanKindRPCServer.Set(span)
		ext.HTTPMethod.Set(span, ctx.Method())
		ext.HTTPUrl.Set(span, ctx.OriginalURL())

		config.spanObserver(span, ctx)

		ctx.SetUserContext(opentracing.ContextWithSpan(ctx.UserContext(), span))
	}

	return span, err
}

func spanContext(ctx *fiber.Ctx, config opts) (opentracing.SpanContext, error) {
	header := make(opentracing.HTTPHeadersCarrier)

	ctx.Request().Header.VisitAll(func(key, value []byte) {
		header.Set(string(key), string(value))
	})

	return config.tracer.Extract(opentracing.HTTPHeaders, header)
}

func endSpan(ctx *fiber.Ctx, span opentracing.Span) {
	status := ctx.Response().StatusCode()
	ext.HTTPStatusCode.Set(span, uint16(status))

	if status >= fiber.StatusInternalServerError {
		ext.Error.Set(span, true)
	}

	span.Finish()
}
