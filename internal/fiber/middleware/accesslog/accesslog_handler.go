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

		logContext := logger.Level(zerolog.InfoLevel).With().
			Int64("_tx_start", start.Unix()).
			Str("_client_ip", c.IP()).
			Str("_http_method", c.Method()).
			Str("_http_path", c.Path()).
			Str("_http_user_agent", c.Get("User-Agent")).
			Str("_http_host", c.Hostname()).
			Str("_http_scheme", string(c.Request().URI().Scheme()))

		if c.IsProxyTrusted() { // nolint: nestif
			if headerValue := c.Get("X-Request-Id"); len(headerValue) != 0 {
				logContext = logContext.Str("_http_x_request_id", headerValue)
			}

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

		accessLogger := logContext.Logger()

		accessLogger.Info().Msg("TX started")

		alc := &Context{}
		c.SetUserContext(context.WithValue(c.UserContext(), ctxKey{}, alc))
		err := c.Next()

		end := time.Now()
		duration := end.Sub(start)

		event := accessLogger.Info().
			Int("_body_bytes_sent", len(c.Response().Body())).
			Int("_http_status_code", c.Response().StatusCode()).
			Int64("_tx_duration_ms", duration.Milliseconds())

		if err != nil {
			event = event.Err(err)
		}

		if alc.Err != nil {
			event = event.Err(alc.Err).Bool("_access_granted", false)
		} else if len(alc.Subject) != 0 {
			event.Str("_subject", alc.Subject).Bool("_access_granted", true)
		}

		event.Msg("TX finished")

		return err
	}
}
