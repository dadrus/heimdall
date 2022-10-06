package logger

import (
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/trace"
)

func New(logger zerolog.Logger) fiber.Handler {
	return func(c *fiber.Ctx) error {
		spanCtx := trace.SpanContextFromContext(c.UserContext())
		logCtx := logger.With()

		if spanCtx.TraceID().IsValid() {
			logCtx = logCtx.Str("_trace_id", spanCtx.TraceID().String())
		}

		if spanCtx.SpanID().IsValid() {
			logCtx = logCtx.Str("_span_id", spanCtx.SpanID().String())
		}

		c.SetUserContext(logCtx.Logger().WithContext(c.UserContext()))

		return c.Next()
	}
}
