package decision

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules"
	"github.com/dadrus/heimdall/internal/x"
)

const (
	xForwardedMethod = "X-Forwarded-Method"
	xForwardedProto  = "X-Forwarded-Proto"
	xForwardedURI    = "X-Forwarded-Uri"
)

type Handler struct {
	r rules.Repository
	s heimdall.JWTSigner
}

type handlerParams struct {
	fx.In

	App             *fiber.App `name:"api"`
	RulesRepository rules.Repository
	Logger          zerolog.Logger
	Signer          heimdall.JWTSigner
}

func newHandler(params handlerParams) (*Handler, error) {
	handler := &Handler{
		r: params.RulesRepository,
		s: params.Signer,
	}

	handler.registerRoutes(params.App.Group(""), params.Logger)

	return handler, nil
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
	logger := zerolog.Ctx(c.UserContext())

	method := h.getRequestMethod(c)
	reqURL := h.getRequestURL(c)

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

	ctx := &requestContext{
		c:           c,
		signer:      h.s,
		reqURL:      reqURL,
		respHeader:  make(http.Header),
		respCookies: make(map[string]string),
	}

	err = rule.Execute(ctx)
	if err == nil {
		err = ctx.err
	}

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

	for k := range ctx.respHeader {
		c.Response().Header.Set(k, ctx.respHeader.Get(k))
	}

	for k, v := range ctx.respCookies {
		c.Cookie(&fiber.Cookie{Name: k, Value: v})
	}

	return c.SendStatus(fiber.StatusOK)
}

func (h *Handler) getRequestURL(c *fiber.Ctx) *url.URL {
	var (
		path   string
		query  string
		scheme string
	)

	if c.IsProxyTrusted() {
		forwardedURIVal := c.Get(xForwardedURI)
		if len(forwardedURIVal) != 0 {
			forwardedURI, _ := url.ParseRequestURI(forwardedURIVal)
			path = forwardedURI.Path
			query = forwardedURI.Query().Encode()
		}
	}

	if len(path) == 0 {
		path = c.Params("*")
		origReqURL := *c.Request().URI()
		query = string(origReqURL.QueryString())
	}

	if c.IsProxyTrusted() {
		scheme = c.Get(xForwardedProto)
	}

	return &url.URL{
		Scheme:   x.OrDefault(scheme, c.Protocol()),
		Host:     c.Hostname(),
		Path:     path,
		RawQuery: query,
	}
}

func (h *Handler) getRequestMethod(c *fiber.Ctx) string {
	if c.IsProxyTrusted() {
		return x.OrDefault(c.Get(xForwardedMethod), c.Method())
	}

	return c.Method()
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

		return c.Redirect(redirectError.RedirectTo.String(), redirectError.Code)
	default:
		return c.SendStatus(fiber.StatusInternalServerError)
	}
}

type requestContext struct {
	c           *fiber.Ctx
	reqURL      *url.URL
	respHeader  http.Header
	respCookies map[string]string
	signer      heimdall.JWTSigner
	err         error
}

func (s *requestContext) RequestHeader(name string) string         { return s.c.Get(name) }
func (s *requestContext) RequestCookie(name string) string         { return s.c.Cookies(name) }
func (s *requestContext) RequestQueryParameter(name string) string { return s.c.Query(name) }
func (s *requestContext) RequestFormParameter(name string) string  { return s.c.FormValue(name) }
func (s *requestContext) RequestBody() []byte                      { return s.c.Body() }
func (s *requestContext) AppContext() context.Context              { return s.c.UserContext() }
func (s *requestContext) SetPipelineError(err error)               { s.err = err }
func (s *requestContext) AddResponseHeader(name, value string)     { s.respHeader.Add(name, value) }
func (s *requestContext) AddResponseCookie(name, value string)     { s.respCookies[name] = value }
func (s *requestContext) Signer() heimdall.JWTSigner               { return s.signer }
func (s *requestContext) RequestURL() *url.URL                     { return s.reqURL }
func (s *requestContext) RequestClientIPs() []string {
	ips := s.c.IPs()
	if len(ips) == 0 {
		ips = append(ips, s.c.IP())
	}

	return ips
}
