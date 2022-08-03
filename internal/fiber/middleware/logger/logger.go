package logger

import (
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

func New(logger zerolog.Logger) fiber.Handler {
	return func(c *fiber.Ctx) error {
		c.SetUserContext(logger.WithContext(c.UserContext()))

		return c.Next()
	}
}
