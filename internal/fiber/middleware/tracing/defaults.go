package tracing

import (
	"github.com/gofiber/fiber/v2"
	"github.com/opentracing/opentracing-go"
)

// nolint: gochecknoglobals
var defaultOptions = opts{
	tracer:                 opentracing.NoopTracer{},
	operationName:          func(ctx *fiber.Ctx) string { return "HTTP " + ctx.Method() + " URL: " + ctx.Path() },
	filterOperation:        func(ctx *fiber.Ctx) bool { return false },
	skipSpansWithoutParent: false,
	modifySpan: func(ctx *fiber.Ctx, span opentracing.Span) {
		span.SetTag("http.method", ctx.Method())
		span.SetTag("http.remote_address", ctx.IP())
		span.SetTag("http.path", ctx.Path())
		span.SetTag("http.host", ctx.Hostname())
		span.SetTag("http.url", ctx.OriginalURL())
	},
}
