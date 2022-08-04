package accesslog

import (
	"context"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

func New(logger zerolog.Logger) fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()

		alc := &accessContext{}
		c.SetUserContext(context.WithValue(c.UserContext(), ctxKey{}, alc))

		accLog := createAccessLogger(c, logger, start)
		accLog.Info().Msg("TX started")

		err := c.Next()

		createAccessLogFinalizationEvent(c, accLog, err, start, alc).Msg("TX finished")

		return err
	}
}

func createAccessLogger(c *fiber.Ctx, logger zerolog.Logger, start time.Time) zerolog.Logger {
	logContext := logger.Level(zerolog.InfoLevel).With().
		Int64("_tx_start", start.Unix()).
		Str("_client_ip", c.IP()).
		Str("_http_method", c.Method()).
		Str("_http_path", c.Path()).
		Str("_http_user_agent", c.Get("User-Agent")).
		Str("_http_host", string(c.Request().URI().Host())).
		Str("_http_scheme", string(c.Request().URI().Scheme()))

	if c.IsProxyTrusted() { // nolint: nestif
		if headerValue := c.Get("X-Forwarded-Proto"); len(headerValue) != 0 {
			logContext = logContext.Str("_http_x_forwarded_proto", headerValue)
		}

		if headerValue := c.Get("X-Forwarded-Host"); len(headerValue) != 0 {
			logContext = logContext.Str("_http_x_forwarded_host", headerValue)
		}

		if headerValue := c.Get("X-Forwarded-Path"); len(headerValue) != 0 {
			logContext = logContext.Str("_http_x_forwarded_path", headerValue)
		}

		if headerValue := c.Get("X-Forwarded-Uri"); len(headerValue) != 0 {
			logContext = logContext.Str("_http_x_forwarded_uri", headerValue)
		}

		if headerValue := c.Get("X-Forwarded-For"); len(headerValue) != 0 {
			logContext = logContext.Str("_http_x_forwarded_for", headerValue)
		}

		if headerValue := c.Get("Forwarded"); len(headerValue) != 0 {
			logContext = logContext.Str("_http_forwarded", headerValue)
		}
	}

	return logContext.Logger()
}

func createAccessLogFinalizationEvent(c *fiber.Ctx, accessLogger zerolog.Logger, err error,
	start time.Time, alc *accessContext,
) *zerolog.Event {
	end := time.Now()
	duration := end.Sub(start)

	event := accessLogger.Info().
		Int("_body_bytes_sent", len(c.Response().Body())).
		Int("_http_status_code", c.Response().StatusCode()).
		Int64("_tx_duration_ms", duration.Milliseconds())

	if err != nil {
		event = event.Err(err)
	}

	if alc.err != nil {
		event = event.Err(alc.err).Bool("_access_granted", false)
	} else if len(alc.subject) != 0 {
		event.Str("_subject", alc.subject).Bool("_access_granted", true)
	}

	return event
}
