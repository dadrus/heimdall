package decision

import (
	"errors"
	"net/url"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules"
	"github.com/dadrus/heimdall/internal/x"
)

const (
	xForwardedMethod = "X-Forwarded-Method"
	xForwardedProto  = "X-Forwarded-Proto"
	xForwardedHost   = "X-Forwarded-Host"
	xForwardedURI    = "X-Forwarded-Uri"
)

type Handler struct {
	r rules.Repository
}

func newHandler(p fiberApp, r rules.Repository, logger zerolog.Logger) *Handler {
	h := &Handler{r: r}
	h.registerRoutes(p.App.Group(""), logger)

	return h
}

func (h *Handler) registerRoutes(router fiber.Router, logger zerolog.Logger) {
	logger.Debug().Msg("Registering decision api routes")

	router.All("/decisions/*", h.decisions)
}

// swagger:route GET /decisions api decisions
//
// Access Control Decision API
//
// > This endpoint works with all HTTP Methods (GET, POST, PUT, ...) and matches every path prefixed with /decision.
//
// This endpoint mirrors the proxy capability of Heimdall's proxy functionality but instead of forwarding the
// request to the upstream server, returns 200 (request should be allowed), 401 (unauthorized), or 403 (forbidden)
// status codes. This endpoint can be used to integrate with other API Proxies like Ambassador, Kong, Envoy, and many
// more.
//
//     Schemes: http, https
//
//     Responses:
//       200: emptyResponse
//       400: genericError
//       401: genericError
//       403: genericError
//       500: genericError
//       503: genericError
func (h *Handler) decisions(c *fiber.Ctx) error {
	ctx := c.UserContext()
	logger := zerolog.Ctx(ctx)

	method := x.OrDefault(c.Get(xForwardedMethod), c.Method())
	reqURL := &url.URL{
		Scheme: x.OrDefault(c.Get(xForwardedProto), c.Protocol()),
		Host:   x.OrDefault(c.Get(xForwardedHost), c.Hostname()),
		Path:   x.OrDefault(c.Get(xForwardedURI), c.Params("*")),
	}

	fields := map[string]interface{}{
		"http_method":     method,
		"http_url":        reqURL.String(),
		"http_host":       c.Hostname(),
		"http_user_agent": c.Get("User-Agent"),
	}

	logger.Info().
		Fields(fields).
		Msg("Handling request")

	rule, err := h.r.FindRule(reqURL)
	if err != nil {
		logger.Warn().
			Fields(fields).
			Bool("granted", false).
			Msg("Access request denied. No rule applicable")

		return c.SendStatus(fiber.StatusInternalServerError)
	}

	if !rule.MatchesMethod(method) {
		return c.SendStatus(fiber.StatusMethodNotAllowed)
	}

	subjectCtx, err := rule.Execute(ctx, &requestContext{c: c})
	if err != nil {
		logger.Info().
			Fields(fields).
			Bool("granted", false).
			Msg("Access request denied")

		return h.handleError(c, err)
	}

	logger.Info().
		Fields(fields).
		Bool("granted", true).
		Msg("Access request granted")

	for k := range subjectCtx.Header {
		c.Response().Header.Set(k, subjectCtx.Header.Get(k))
	}

	return c.SendStatus(fiber.StatusOK)
}

func (h *Handler) handleError(c *fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, heimdall.ErrArgument):
		return c.SendStatus(fiber.StatusBadRequest)
	case errors.Is(err, heimdall.ErrAuthentication):
		return c.SendStatus(fiber.StatusUnauthorized)
	case errors.Is(err, heimdall.ErrAuthorization):
		return c.SendStatus(fiber.StatusForbidden)
	case errors.Is(err, heimdall.ErrCommunicationTimeout):
		return c.SendStatus(fiber.StatusBadGateway)
	case errors.Is(err, &heimdall.RedirectError{}):
		var redirectError *heimdall.RedirectError

		errors.As(err, &redirectError)

		return c.Redirect(redirectError.RedirectTo)
	default:
		return c.SendStatus(fiber.StatusInternalServerError)
	}
}

type requestContext struct {
	c *fiber.Ctx
}

func (s *requestContext) Header(name string) string { return s.c.Get(name) }
func (s *requestContext) Cookie(name string) string { return s.c.Cookies(name) }
func (s *requestContext) Query(name string) string  { return s.c.Query(name) }
func (s *requestContext) Form(name string) string   { return s.c.FormValue(name) }
func (s *requestContext) Body() []byte              { return s.c.Body() }
