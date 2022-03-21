package decision

import (
	"net/url"

	"github.com/dadrus/heimdall/rule"
	"github.com/dadrus/heimdall/x"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

const (
	xForwardedMethod = "X-Forwarded-Method"
	xForwardedProto  = "X-Forwarded-Proto"
	xForwardedHost   = "X-Forwarded-Host"
	xForwardedUri    = "X-Forwarded-Uri"
)

type Handler struct {
	rm rule.RuleMatcher
}

func newHandler(p fiberApp, rm rule.RuleMatcher, logger zerolog.Logger) *Handler {
	h := &Handler{
		rm: rm,
	}

	h.registerRoutes(p.App.Group(""), logger)
	return h
}

func (h *Handler) registerRoutes(router fiber.Router, logger zerolog.Logger) {
	logger.Debug().Msg("Registering decision api routes")

	router.Get("/decisions/*", h.decisions)
}

// swagger:route GET /decisions api decisions
//
// Access Control Decision API
//
// > This endpoint works with all HTTP Methods (GET, POST, PUT, ...) and matches every path prefixed with /decision.
//
// This endpoint mirrors the proxy capability of ORY Oathkeeper's proxy functionality but instead of forwarding the
// request to the upstream server, returns 200 (request should be allowed), 401 (unauthorized), or 403 (forbidden)
// status codes. This endpoint can be used to integrate with other API Proxies like Ambassador, Kong, Envoy, and many more.
//
//     Schemes: http, https
//
//     Responses:
//       200: emptyResponse
//       401: genericError
//       403: genericError
//       404: genericError
//       500: genericError
func (h *Handler) decisions(c *fiber.Ctx) error {
	ctx := c.UserContext()
	logger := zerolog.Ctx(ctx)

	method := x.OrDefault(c.Get(xForwardedMethod), c.Method())
	reqUrl := &url.URL{
		Scheme: x.OrDefault(c.Get(xForwardedProto), c.Protocol()),
		Host:   x.OrDefault(c.Get(xForwardedHost), c.Hostname()),
		Path:   x.OrDefault(c.Get(xForwardedUri), c.Params("*")),
	}

	fields := map[string]interface{}{
		"http_method":     method,
		"http_url":        reqUrl.String(),
		"http_host":       c.Hostname(),
		"http_user_agent": c.Get("User-Agent"),
	}

	logger.Warn().Fields(fields).
		Bool("granted", false).
		Msg("Access request denied")

	return c.SendStatus(fiber.StatusOK)
}
