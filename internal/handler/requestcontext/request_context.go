package requestcontext

import (
	"context"
	"net/http"
	"net/url"

	"github.com/gofiber/fiber/v2"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x"
)

type RequestContext struct {
	c           *fiber.Ctx
	reqURL      *url.URL
	respHeaders http.Header
	respCookies map[string]string
	jwtSigner   heimdall.JWTSigner
	err         error
}

func New(c *fiber.Ctx, reqURL *url.URL, signer heimdall.JWTSigner) *RequestContext {
	return &RequestContext{
		c:           c,
		jwtSigner:   signer,
		reqURL:      reqURL,
		respHeaders: make(http.Header),
		respCookies: make(map[string]string),
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
func (s *RequestContext) AddResponseHeader(name, value string)     { s.respHeaders.Add(name, value) }
func (s *RequestContext) AddResponseCookie(name, value string)     { s.respCookies[name] = value }
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

	for k := range s.respHeaders {
		s.c.Response().Header.Set(k, s.respHeaders.Get(k))
	}

	for k, v := range s.respCookies {
		s.c.Cookie(&fiber.Cookie{Name: k, Value: v})
	}

	return nil
}
