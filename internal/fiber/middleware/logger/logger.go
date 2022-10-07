package logger

import (
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/x/opentelemetry/tracecontext"
)

func New(logger zerolog.Logger) fiber.Handler {
	return func(c *fiber.Ctx) error {
		logCtx := logger.With()
		traceCtx := tracecontext.Extract(c.UserContext())

		if traceCtx != nil {
			logCtx = logCtx.
				Str("_trace_id", traceCtx.TraceID).
				Str("_span_id", traceCtx.SpanID)

			if len(traceCtx.ParentID) != 0 {
				logCtx = logCtx.Str("_parent_id", traceCtx.ParentID)
			}
		}

		c.SetUserContext(logCtx.Logger().WithContext(c.UserContext()))

		return c.Next()
	}
}
