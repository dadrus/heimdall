package opentel

import (
	"github.com/gofiber/fiber/v2"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

// nolint: gochecknoglobals
var defaultOptions = opts{
	tracer: otel.GetTracerProvider().
		Tracer("github.com/dadrus/heimdall/internal/fiber/middleware/opentel",
			trace.WithInstrumentationVersion("semver:0.1.0")),
	operationName:          func(ctx *fiber.Ctx) string { return "HTTP " + ctx.Method() + " URL: " + ctx.Path() },
	filterOperation:        func(ctx *fiber.Ctx) bool { return false },
	skipSpansWithoutParent: false,
	spanObserver:           func(ctx *fiber.Ctx, span trace.Span) {},
}
