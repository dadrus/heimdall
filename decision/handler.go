package decision

import (
	"context"
	"net/url"

	"github.com/dadrus/heimdall/errorsx"
	"github.com/dadrus/heimdall/pipeline"
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
	r executorRepo
}

func newHandler(p fiberApp, logger zerolog.Logger) *Handler {
	h := &Handler{}

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
// status codes. This endpoint can be used to integrate with other API Proxies like Ambassador, Kong, Envoy, and many more.
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

	logger.Info().
		Fields(fields).
		Msg("Handling request")

	r, err := h.r.FindRule(method, reqUrl)
	if err != nil {
		logger.Warn().
			Fields(fields).
			Bool("granted", false).
			Msg("Access request denied. No rule applicable")

		return c.SendStatus(fiber.StatusInternalServerError)
	}

	sc, err := r.Execute(ctx, &authDataSource{c: c})
	if err != nil {
		logger.Warn().
			Fields(fields).
			Bool("granted", false).
			Msg("Access request denied")

		switch err.(type) {
		case *errorsx.ArgumentError:
			return c.SendStatus(fiber.StatusBadRequest)
		case *errorsx.ForbiddenError:
			return c.SendStatus(fiber.StatusForbidden)
		case *errorsx.UnauthorizedError:
			return c.SendStatus(fiber.StatusUnauthorized)
		case *errorsx.RemoteCallError:
			return c.SendStatus(fiber.StatusBadGateway)
		default:
			return c.SendStatus(fiber.StatusInternalServerError)
		}
	}

	if len(sc.RedirectTo) != 0 {
		logger.Info().
			Fields(fields).
			Bool("granted", false).
			Msg("Access request denied. Redirect triggered.")

		return c.Redirect(sc.RedirectTo)
	}

	logger.Info().
		Fields(fields).
		Bool("granted", true).
		Msg("Access request granted")

	for k, _ := range sc.Header {
		c.Response().Header.Set(k, sc.Header.Get(k))
	}

	return c.SendStatus(fiber.StatusOK)
}

type authDataSource struct {
	c *fiber.Ctx
}

func (s *authDataSource) Header(name string) string { return s.c.Get(name) }
func (s *authDataSource) Cookie(name string) string { return s.c.Cookies(name) }
func (s *authDataSource) Query(name string) string  { return s.c.Query(name) }
func (s *authDataSource) Form(name string) string   { return s.c.FormValue(name) }

type executor interface {
	Execute(ctx context.Context, source pipeline.AuthDataSource) (*pipeline.SubjectContext, error)
}

type executorRepo interface {
	FindRule(method string, requestUrl *url.URL) (executor, error)
}
