package requestcontext

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"

	"github.com/dadrus/heimdall/internal/fasthttp/tracing"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x"
)

type RequestContext struct {
	c               *fiber.Ctx
	reqURL          *url.URL
	upstreamHeaders http.Header
	upstreamCookies map[string]string
	jwtSigner       heimdall.JWTSigner
	err             error
}

func New(c *fiber.Ctx, reqURL *url.URL, signer heimdall.JWTSigner) *RequestContext {
	return &RequestContext{ //nolint:exhaustruct
		c:               c,
		jwtSigner:       signer,
		reqURL:          reqURL,
		upstreamHeaders: make(http.Header),
		upstreamCookies: make(map[string]string),
	}
}

func (s *RequestContext) RequestMethod() string                    { return s.c.Method() }
func (s *RequestContext) RequestHeaders() map[string]string        { return s.c.GetReqHeaders() }
func (s *RequestContext) RequestHeader(name string) string         { return s.c.Get(name) }
func (s *RequestContext) RequestCookie(name string) string         { return s.c.Cookies(name) }
func (s *RequestContext) RequestQueryParameter(name string) string { return s.c.Query(name) }
func (s *RequestContext) RequestFormParameter(name string) string  { return s.c.FormValue(name) }
func (s *RequestContext) RequestBody() []byte                      { return s.c.Body() }
func (s *RequestContext) AppContext() context.Context              { return s.c.UserContext() }
func (s *RequestContext) SetPipelineError(err error)               { s.err = err }
func (s *RequestContext) AddHeaderForUpstream(name, value string)  { s.upstreamHeaders.Add(name, value) }
func (s *RequestContext) AddCookieForUpstream(name, value string)  { s.upstreamCookies[name] = value }
func (s *RequestContext) Signer() heimdall.JWTSigner               { return s.jwtSigner }
func (s *RequestContext) RequestURL() *url.URL                     { return s.reqURL }
func (s *RequestContext) RequestClientIPs() []string {
	ips := s.c.IPs()

	return x.IfThenElse(len(ips) != 0, ips, []string{s.c.IP()})
}

func (s *RequestContext) Finalize() error {
	if s.err != nil {
		return s.err
	}

	for k := range s.upstreamHeaders {
		s.c.Response().Header.Set(k, s.upstreamHeaders.Get(k))
	}

	for k, v := range s.upstreamCookies {
		s.c.Cookie(&fiber.Cookie{Name: k, Value: v})
	}

	s.c.Status(fiber.StatusAccepted)

	return nil
}

func (s *RequestContext) FinalizeAndForward(method string, upstreamURL *url.URL, timeout time.Duration) error {
	if s.err != nil {
		return s.err
	}

	for k := range s.upstreamHeaders {
		s.c.Request().Header.Set(k, s.upstreamHeaders.Get(k))
	}

	for k, v := range s.upstreamCookies {
		s.c.Request().Header.SetCookie(k, v)
	}

	// delete headers, which are useless for the upstream service, before forwarding the request
	for _, name := range []string{
		"X-Forwarded-Method", "X-Forwarded-Proto", "X-Forwarded-Host", "X-Forwarded-Uri", "X-Forwarded-Path",
	} {
		s.c.Request().Header.Del(name)
	}

	s.c.Request().Header.SetMethod(method)
	s.c.Request().SetRequestURI(upstreamURL.String())

	return tracing.NewClient(&fasthttp.Client{}).DoTimeout(s.c.UserContext(), s.c.Request(), s.c.Response(), timeout)
}
