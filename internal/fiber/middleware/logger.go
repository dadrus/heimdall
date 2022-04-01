package middleware

import (
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog/log"
)

func Logger() fiber.Handler {
	return func(c *fiber.Ctx) error {
		l := log.With().Logger()

		c.SetUserContext(l.WithContext(c.UserContext()))

		return c.Next()
	}
}
