package decision

import (
	"context"
	"net/http"
	"net/url"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/fiber/middleware/xforwarded"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
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

func (h *Handler) decisions(c *fiber.Ctx) error {
	reqURL := xforwarded.RequestURL(c.UserContext())

	rule, err := h.r.FindRule(reqURL)
	if err != nil {
		return errorchain.NewWithMessage(heimdall.ErrInternal, "no applicable rule found").CausedBy(err)
	}

	method := xforwarded.RequestMethod(c.UserContext())
	if !rule.MatchesMethod(method) {
		return errorchain.NewWithMessage(heimdall.ErrMethodNotAllowed, "rule doesn't match method")
	}

	ctx := &requestContext{
		c:           c,
		signer:      h.s,
		reqURL:      reqURL,
		respHeaders: make(http.Header),
		respCookies: make(map[string]string),
	}

	err = rule.Execute(ctx)
	if err == nil {
		err = ctx.err
	}

	if err != nil {
		return err
	}

	for k := range ctx.respHeaders {
		c.Response().Header.Set(k, ctx.respHeaders.Get(k))
	}

	for k, v := range ctx.respCookies {
		c.Cookie(&fiber.Cookie{Name: k, Value: v})
	}

	c.Status(fiber.StatusAccepted)

	return nil
}

type requestContext struct {
	c           *fiber.Ctx
	reqURL      *url.URL
	respHeaders http.Header
	respCookies map[string]string
	signer      heimdall.JWTSigner
	err         error
}

func (s *requestContext) RequestMethod() string                    { return s.c.Method() }
func (s *requestContext) RequestHeaders() map[string]string        { return s.c.GetReqHeaders() }
func (s *requestContext) RequestHeader(name string) string         { return s.c.Get(name) }
func (s *requestContext) RequestCookie(name string) string         { return s.c.Cookies(name) }
func (s *requestContext) RequestQueryParameter(name string) string { return s.c.Query(name) }
func (s *requestContext) RequestFormParameter(name string) string  { return s.c.FormValue(name) }
func (s *requestContext) RequestBody() []byte                      { return s.c.Body() }
func (s *requestContext) AppContext() context.Context              { return s.c.UserContext() }
func (s *requestContext) SetPipelineError(err error)               { s.err = err }
func (s *requestContext) AddResponseHeader(name, value string)     { s.respHeaders.Add(name, value) }
func (s *requestContext) AddResponseCookie(name, value string)     { s.respCookies[name] = value }
func (s *requestContext) Signer() heimdall.JWTSigner               { return s.signer }
func (s *requestContext) RequestURL() *url.URL                     { return s.reqURL }
func (s *requestContext) RequestClientIPs() []string {
	ips := s.c.IPs()

	return x.IfThenElse(len(ips) != 0, ips, []string{s.c.IP()})
}
