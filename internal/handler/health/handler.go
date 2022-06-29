package health

import (
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

func RegisterRoutes(router fiber.Router, logger zerolog.Logger) {
	logger.Debug().Msg("Registering health route")

	router.Get("/.well-known/health", health)
}

func health(c *fiber.Ctx) error {
	type status struct {
		Status string `json:"status"`
	}

	return c.JSON(status{Status: "ok"})
}
