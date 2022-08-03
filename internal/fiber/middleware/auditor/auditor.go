package auditor

import (
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/fiber/middleware/xfmphu"
)

func New(logger zerolog.Logger) fiber.Handler {
	return func(c *fiber.Ctx) error {
		accessLogger := logger.Level(zerolog.InfoLevel)

		reqMethod := xfmphu.RequestMethod(c.UserContext())
		reqURL := xfmphu.RequestURL(c.UserContext())

		fields := map[string]interface{}{
			"client_ip":        c.IP(),
			"method":           c.Method(),
			"path":             c.Path(),
			"user_agent":       c.Get("User-Agent"),
			"host":             c.Hostname(),
			"requested_method": reqMethod,
			"requested_url":    reqURL.String(),
		}

		accessLogger.Info().Fields(fields).Msg("Handling of request")

		err := c.Next()

		fields["payload_size"] = len(c.Response().Body())
		fields["response_code"] = c.Response().StatusCode()

		if err != nil {
			accessLogger.Info().
				Fields(fields).Err(err).Bool("access_granted", false).Msg("Handling of request done")
		} else {
			accessLogger.Info().
				Fields(fields).Bool("access_granted", true).Msg("Handling of request done")
		}

		return err
	}
}
