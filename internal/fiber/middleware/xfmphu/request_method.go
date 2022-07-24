package xfmphu

import (
	"github.com/gofiber/fiber/v2"
)

func requestMethod(c *fiber.Ctx) string {
	if c.IsProxyTrusted() {
		forwardedMethodVal := c.Get(xForwardedMethod)
		if len(forwardedMethodVal) != 0 {
			return forwardedMethodVal
		}
	}

	return c.Method()
}
