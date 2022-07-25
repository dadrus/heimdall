package proxyheader

import (
	"fmt"

	"github.com/gofiber/fiber/v2"

	"github.com/dadrus/heimdall/internal/x"
)

const (
	headerForwarded     = "Forwarded"
	headerXForwardedFor = "X-Forwarded-For"
)

func New() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// reuse already present headers only, if the source is trusted
		// otherwise delete these to avoid sending them to the upstream service
		// these headers shall not be set by the ultimate client
		forwardedForHeaderValue := c.Get(headerXForwardedFor)
		if !c.IsProxyTrusted() && len(forwardedForHeaderValue) != 0 {
			c.Request().Header.Del(headerXForwardedFor)

			forwardedForHeaderValue = ""
		}

		forwardedHeaderValue := c.Get(headerForwarded)
		if !c.IsProxyTrusted() && len(forwardedHeaderValue) != 0 {
			c.Request().Header.Del(headerForwarded)

			forwardedHeaderValue = ""
		}

		clientIP := c.IP()
		proto := string(c.Request().URI().Scheme())

		// Set the X-Forwarded-For (if present), or the "new" Forwarded header
		if len(forwardedForHeaderValue) != 0 {
			c.Request().Header.Set(headerXForwardedFor,
				fmt.Sprintf("%s, %s", forwardedForHeaderValue, clientIP))
		}

		if len(forwardedHeaderValue) != 0 {
			c.Request().Header.Set(headerForwarded,
				x.IfThenElseExec(len(forwardedHeaderValue) == 0,
					func() string { return fmt.Sprintf("for=%s;proto=%s", clientIP, proto) },
					func() string { return fmt.Sprintf("%s, for=%s;proto=%s", forwardedHeaderValue, clientIP, proto) }))
		}

		return c.Next()
	}
}
