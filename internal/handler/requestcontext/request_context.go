// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package requestcontext

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"github.com/valyala/fasthttp"

	"github.com/dadrus/heimdall/internal/fasthttp/opentelemetry"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x"
)

type RequestContext struct {
	c               *fiber.Ctx
	reqMethod       string
	reqURL          *url.URL
	upstreamHeaders http.Header
	upstreamCookies map[string]string
	jwtSigner       heimdall.JWTSigner
	err             error
}

func New(c *fiber.Ctx, method string, reqURL *url.URL, signer heimdall.JWTSigner) *RequestContext {
	return &RequestContext{
		c:               c,
		jwtSigner:       signer,
		reqMethod:       method,
		reqURL:          reqURL,
		upstreamHeaders: make(http.Header),
		upstreamCookies: make(map[string]string),
	}
}

func (s *RequestContext) Request() *heimdall.Request {
	return &heimdall.Request{
		RequestFunctions: s,
		Method:           s.reqMethod,
		URL:              s.reqURL,
		ClientIP:         s.RequestClientIPs(),
	}
}

func (s *RequestContext) Headers() map[string]string              { return s.c.GetReqHeaders() }
func (s *RequestContext) Header(name string) string               { return s.c.Get(name) }
func (s *RequestContext) Cookie(name string) string               { return s.c.Cookies(name) }
func (s *RequestContext) Body() []byte                            { return s.c.Body() }
func (s *RequestContext) AppContext() context.Context             { return s.c.UserContext() }
func (s *RequestContext) SetPipelineError(err error)              { s.err = err }
func (s *RequestContext) AddHeaderForUpstream(name, value string) { s.upstreamHeaders.Add(name, value) }
func (s *RequestContext) AddCookieForUpstream(name, value string) { s.upstreamCookies[name] = value }
func (s *RequestContext) Signer() heimdall.JWTSigner              { return s.jwtSigner }
func (s *RequestContext) RequestClientIPs() []string {
	ips := s.c.IPs()

	return x.IfThenElse(len(ips) != 0, ips, []string{s.c.IP()})
}

func (s *RequestContext) Finalize(statusCode int) error {
	if s.err != nil {
		return s.err
	}

	for k := range s.upstreamHeaders {
		s.c.Response().Header.Set(k, s.upstreamHeaders.Get(k))
	}

	for k, v := range s.upstreamCookies {
		s.c.Cookie(&fiber.Cookie{Name: k, Value: v})
	}

	s.c.Status(statusCode)

	return nil
}

type URIMutator interface {
	Mutate(uri *url.URL) (*url.URL, error)
}

func (s *RequestContext) FinalizeAndForward(mutator URIMutator, timeout time.Duration) error {
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
		"X-Forwarded-Method", "X-Forwarded-Uri", "X-Forwarded-Path",
	} {
		s.c.Request().Header.Del(name)
	}

	targetURL, err := mutator.Mutate(s.reqURL)
	if err != nil {
		return err
	}

	upstreamURL := targetURL.String()

	logger := zerolog.Ctx(s.c.UserContext())
	logger.Info().
		Str("_method", s.reqMethod).
		Str("_upstream", upstreamURL).
		Msg("Forwarding request")

	s.c.Request().Header.SetMethod(s.reqMethod)
	s.c.Request().SetRequestURI(upstreamURL)

	return opentelemetry.NewClient(&fasthttp.Client{}).
		DoTimeout(s.c.UserContext(), s.c.Request(), s.c.Response(), timeout)
}

