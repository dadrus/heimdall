// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
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

package decision

import (
	"net/http"
	"net/url"
	"slices"
	"sync"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/handler/requestcontext"
	"github.com/dadrus/heimdall/internal/pipeline"
)

var _ pipeline.UpstreamRequest = (*requestContext)(nil)

type contextFactory struct {
	responseCode int
	pool         *sync.Pool
}

func (cf *contextFactory) Create(rw http.ResponseWriter, req *http.Request) requestcontext.Context {
	rc := cf.pool.Get().(*requestContext) //nolint: forcetypeassert

	rc.Init(rw, req, cf.responseCode)

	return rc
}

func (cf *contextFactory) Destroy(ctx requestcontext.Context) {
	rc := ctx.(*requestContext) //nolint: forcetypeassert

	rc.Reset()

	cf.pool.Put(rc)
}

func newContextFactory(
	responseCode int,
) requestcontext.ContextFactory {
	return &contextFactory{
		responseCode: responseCode,
		pool: &sync.Pool{New: func() any {
			return &requestContext{
				RequestContext: requestcontext.New(),
			}
		}},
	}
}

type requestContext struct {
	*requestcontext.RequestContext

	req          *http.Request
	rw           http.ResponseWriter
	responseCode int

	replacedHeaders  http.Header
	upstreamPrepared bool
}

func (r *requestContext) Init(rw http.ResponseWriter, req *http.Request, code int) {
	r.rw = rw
	r.req = req
	r.responseCode = code

	r.RequestContext.Init(req)
}

func (r *requestContext) Reset() {
	r.rw = nil
	r.req = nil
	r.responseCode = 0
	r.upstreamPrepared = false
	r.replacedHeaders = nil

	r.RequestContext.Reset()
}

func (r *requestContext) PrepareUpstreamRequest(_ pipeline.UpstreamTarget) {
	r.upstreamPrepared = true
}

func (r *requestContext) UpstreamRequest() pipeline.UpstreamRequest {
	if !r.upstreamPrepared {
		return nil
	}

	return r
}

func (r *requestContext) Method() string               { return r.Request().Method }
func (r *requestContext) Authority() string            { return r.Request().URL.Host }
func (r *requestContext) URL() url.URL                 { return r.Request().URL.URL }
func (r *requestContext) AddHeader(name, value string) { r.AddHeaderForUpstream(name, value) }
func (r *requestContext) SetCookie(name, value string) { r.AddCookieForUpstream(name, value) }

func (r *requestContext) HeaderSnapshot() http.Header {
	var headers http.Header

	if r.replacedHeaders != nil {
		headers = r.replacedHeaders.Clone()
	} else {
		headers = r.req.Header.Clone()
	}

	for name, values := range r.UpstreamHeaders() {
		headers.Del(name)

		for _, value := range values {
			headers.Add(name, value)
		}
	}

	req := http.Request{
		Header: headers,
	}

	r.addUpstreamCookies(&req)

	req.Header.Del("Host")

	return req.Header
}

func (r *requestContext) ReplaceHeaders(headers http.Header) {
	r.replacedHeaders = headers

	if r.replacedHeaders == nil {
		r.replacedHeaders = make(http.Header)
	}

	r.replacedHeaders.Del("Host")

	clear(r.UpstreamHeaders())
	clear(r.UpstreamCookies())
}

//nolint:cyclop
func (r *requestContext) Finalize() error {
	if err := r.Error(); err != nil {
		return err
	}

	zerolog.Ctx(r.Context()).Debug().Msg("Creating response")

	if r.replacedHeaders != nil {
		headers := r.HeaderSnapshot()

		for name, values := range headers {
			if slices.Equal(values, r.req.Header.Values(name)) {
				continue
			}

			for _, value := range values {
				r.rw.Header().Add(name, value)
			}
		}
	} else {
		uh := r.UpstreamHeaders()

		for name, values := range uh {
			if http.CanonicalHeaderKey(name) == "Cookie" {
				continue
			}

			for _, value := range values {
				r.rw.Header().Add(name, value)
			}
		}

		if len(uh.Values("Cookie")) != 0 || len(r.UpstreamCookies()) != 0 {
			for _, value := range r.HeaderSnapshot().Values("Cookie") {
				r.rw.Header().Add("Cookie", value)
			}
		}
	}

	r.rw.WriteHeader(r.responseCode)

	return nil
}

func (r *requestContext) addUpstreamCookies(req *http.Request) {
	for name, value := range r.UpstreamCookies() {
		req.AddCookie(&http.Cookie{Name: name, Value: value}) //nolint:gosec
	}
}
