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

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x"
)

type finalizer func(rule.Backend) error

type RequestContext struct {
	c               *fiber.Ctx
	reqMethod       string
	reqURL          *url.URL
	upstreamHeaders http.Header
	upstreamCookies map[string]string
	jwtSigner       heimdall.JWTSigner
	responseCode    int
	err             error
	finalize        finalizer
}

func (s *RequestContext) Request() *heimdall.Request {
	return &heimdall.Request{
		RequestFunctions: s,
		Method:           s.reqMethod,
		URL:              s.reqURL,
		ClientIP:         s.requestClientIPs(),
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
func (s *RequestContext) requestClientIPs() []string {
	ips := s.c.IPs()

	return x.IfThenElse(len(ips) != 0, ips, []string{s.c.IP()})
}

func (s *RequestContext) Finalize(backend rule.Backend) error {
	logger := zerolog.Ctx(s.c.UserContext())
	logger.Debug().Msg("Finalizing request")

	if s.err != nil {
		return s.err
	}

	return s.finalize(backend)
}

func (s *RequestContext) finalizeWithStatus(_ rule.Backend) error {
	for k := range s.upstreamHeaders {
		s.c.Response().Header.Set(k, s.upstreamHeaders.Get(k))
	}

	for k, v := range s.upstreamCookies {
		s.c.Cookie(&fiber.Cookie{Name: k, Value: v})
	}

	s.c.Status(s.responseCode)

	return nil
}

type ContextFactory interface {
	Create(c *fiber.Ctx) *RequestContext
}

type factoryFunc func(c *fiber.Ctx) *RequestContext

func (f factoryFunc) Create(c *fiber.Ctx) *RequestContext {
	return f(c)
}

func NewDecisionContextFactory(signer heimdall.JWTSigner, responseCode int) ContextFactory {
	return factoryFunc(func(ctx *fiber.Ctx) *RequestContext {
		rc := &RequestContext{
			jwtSigner:       signer,
			reqMethod:       extractMethod(ctx),
			reqURL:          extractURL(ctx),
			upstreamHeaders: make(http.Header),
			upstreamCookies: make(map[string]string),
			c:               ctx,
			responseCode:    responseCode,
		}

		rc.finalize = rc.finalizeWithStatus

		return rc
	})
}
