package xforwarded

import (
	"github.com/gofiber/fiber/v2"

	"github.com/dadrus/heimdall/internal/x"
)

func requestMethod(c *fiber.Ctx) string {
	if c.IsProxyTrusted() {
		return x.OrDefault(c.Get(xForwardedMethod), c.Method())
	}

	return c.Method()
}
