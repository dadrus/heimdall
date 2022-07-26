package auditor

import (
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog/log"

	"github.com/dadrus/heimdall/internal/fiber/middleware/xfmphu"
)

func New() fiber.Handler {
	return func(c *fiber.Ctx) error {
		logger := log.With().Logger()

		method := xfmphu.RequestMethod(c.UserContext())
		reqURL := xfmphu.RequestURL(c.UserContext())

		fields := map[string]interface{}{
			"http_method":     method,
			"http_url":        reqURL.String(),
			"http_host":       c.Hostname(),
			"http_user_agent": c.Get("User-Agent"),
		}

		logger.Info().Fields(fields).Msg("Handling request")

		err := c.Next()
		if err != nil {
			logger.Warn().Fields(fields).Err(err).Bool("granted", false).Msg("Access request denied.")
		} else {
			logger.Info().Fields(fields).Bool("granted", true).Msg("Access request granted.")
		}

		return err
	}
}
