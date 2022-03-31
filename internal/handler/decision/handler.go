package decision

import (
	"errors"
	"net/url"

	"github.com/dadrus/heimdall/internal/rules"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/errorsx"
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
func (h *Handler) decisions(reqCtx *fiber.Ctx) error {
	ctx := reqCtx.UserContext()
	logger := zerolog.Ctx(ctx)

	method := x.OrDefault(reqCtx.Get(xForwardedMethod), reqCtx.Method())
	reqURL := &url.URL{
		Scheme: x.OrDefault(reqCtx.Get(xForwardedProto), reqCtx.Protocol()),
		Host:   x.OrDefault(reqCtx.Get(xForwardedHost), reqCtx.Hostname()),
		Path:   x.OrDefault(reqCtx.Get(xForwardedURI), reqCtx.Params("*")),
	}

	fields := map[string]interface{}{
		"http_method":     method,
		"http_url":        reqURL.String(),
		"http_host":       reqCtx.Hostname(),
		"http_user_agent": reqCtx.Get("User-Agent"),
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

		return reqCtx.SendStatus(fiber.StatusInternalServerError)
	}

	if !rule.MatchesMethod(method) {
		return reqCtx.SendStatus(fiber.StatusMethodNotAllowed)
	}

	subjectCtx, err := rule.Execute(ctx, &requestContext{c: reqCtx})
	if err != nil {
		logger.Warn().
			Fields(fields).
			Bool("granted", false).
			Msg("Access request denied")

		return h.handleError(reqCtx, err)
	}

	logger.Info().
		Fields(fields).
		Bool("granted", true).
		Msg("Access request granted")

	for k := range subjectCtx.Header {
		reqCtx.Response().Header.Set(k, subjectCtx.Header.Get(k))
	}

	return reqCtx.SendStatus(fiber.StatusOK)
}

func (h *Handler) handleError(ctx *fiber.Ctx, err error) error {
	if errors.Is(err, &errorsx.ArgumentError{}) {
		return ctx.SendStatus(fiber.StatusBadRequest)
	} else if errors.Is(err, &errorsx.ForbiddenError{}) {
		return ctx.SendStatus(fiber.StatusForbidden)
	} else if errors.Is(err, &errorsx.UnauthorizedError{}) {
		return ctx.SendStatus(fiber.StatusUnauthorized)
	} else if errors.Is(err, &errorsx.RemoteCallError{}) {
		return ctx.SendStatus(fiber.StatusBadGateway)
	} else if errors.Is(err, &errorsx.RedirectError{}) {
		var redirectError *errorsx.RedirectError
		errors.As(err, &redirectError)

		return ctx.Redirect(redirectError.RedirectTo)
	} else {
		return ctx.SendStatus(fiber.StatusInternalServerError)
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
