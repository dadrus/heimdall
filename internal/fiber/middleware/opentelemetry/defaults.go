package opentelemetry

import (
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v2"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

const (
	tracerName    = "github.com/dadrus/heimdall/internal/fiber/middleware/opentel"
	tracerVersion = "semver:0.1.0"
)

// nolint: gochecknoglobals
var defaultOptions = opts{
	tracer: otel.GetTracerProvider().Tracer(tracerName, trace.WithInstrumentationVersion(tracerVersion)),
	operationName: func(ctx *fiber.Ctx) string {
		return fmt.Sprintf("EntryPoint %s %s%s",
			strings.ToLower(ctx.Protocol()), ctx.Context().LocalAddr().String(), ctx.Path())
	},
	filterOperation:        func(ctx *fiber.Ctx) bool { return false },
	skipSpansWithoutParent: false,
	spanObserver:           func(ctx *fiber.Ctx, span trace.Span) {},
}
