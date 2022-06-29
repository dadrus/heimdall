package health

import (
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

const EndpointHealth = "/.well-known/health"

func RegisterRoutes(router fiber.Router, logger zerolog.Logger) {
	logger.Debug().Msg("Registering health route")

	router.Get(EndpointHealth, health)
}

func health(c *fiber.Ctx) error {
	type status struct {
		Status string `json:"status"`
	}

	return c.JSON(status{Status: "ok"})
}
