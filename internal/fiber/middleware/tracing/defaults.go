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
	spanObserver:           func(span opentracing.Span, ctx *fiber.Ctx) {},
}
