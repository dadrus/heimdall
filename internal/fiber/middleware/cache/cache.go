package cache

import (
	"github.com/gofiber/fiber/v2"

	"github.com/dadrus/heimdall/internal/cache"
)

func New(cch cache.Cache) fiber.Handler {
	return func(c *fiber.Ctx) error {
		c.SetUserContext(cache.WithContext(c.UserContext(), cch))

		return c.Next()
	}
}
