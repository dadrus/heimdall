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

package requestcontext

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/contenttype"
	"github.com/dadrus/heimdall/internal/x/httpx"
	"github.com/dadrus/heimdall/internal/x/slicex"
)

type RequestContext struct {
	reqMethod       string
	reqURL          *url.URL
	upstreamHeaders http.Header
	upstreamCookies map[string]string
	jwtSigner       heimdall.JWTSigner
	req             *http.Request
	err             error

	// the following properties are created lazy and cached

	savedBody any
	hmdlReq   *heimdall.Request
	headers   map[string]string
	outputs   map[string]any
}

func New(signer heimdall.JWTSigner, req *http.Request) *RequestContext {
	return &RequestContext{
		jwtSigner:       signer,
		reqMethod:       extractMethod(req),
		reqURL:          extractURL(req),
		upstreamHeaders: make(http.Header),
		upstreamCookies: make(map[string]string),
		req:             req,
	}
}

func (r *RequestContext) Header(name string) string {
	key := textproto.CanonicalMIMEHeaderKey(name)
	if key == "Host" {
		return r.req.Host
	}

	return strings.Join(r.req.Header.Values(key), ",")
}

func (r *RequestContext) Cookie(name string) string {
	if cookie, err := r.req.Cookie(name); err == nil {
		return cookie.Value
	}

	return ""
}

func (r *RequestContext) Headers() map[string]string {
	if len(r.headers) == 0 {
		r.headers = make(map[string]string, len(r.req.Header)+1)

		r.headers["Host"] = r.req.Host
		for k, v := range r.req.Header {
			r.headers[textproto.CanonicalMIMEHeaderKey(k)] = strings.Join(v, ",")
		}
	}

	return r.headers
}

func (r *RequestContext) Body() any {
	if r.req.Body == nil || r.req.Body == http.NoBody {
		return ""
	}

	if r.savedBody == nil {
		// drain body by reading its contents into memory and preserving
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(r.req.Body); err != nil {
			return ""
		}

		if err := r.req.Body.Close(); err != nil {
			return ""
		}

		body := buf.Bytes()
		r.req.Body = io.NopCloser(bytes.NewReader(body))

		decoder, err := contenttype.NewDecoder(r.Header("Content-Type"))
		if err != nil {
			r.savedBody = string(body)

			return r.savedBody
		}

		data, err := decoder.Decode(body)
		if err != nil {
			r.savedBody = string(body)

			return r.savedBody
		}

		r.savedBody = data
	}

	return r.savedBody
}

func (r *RequestContext) Request() *heimdall.Request {
	if r.hmdlReq == nil {
		r.hmdlReq = &heimdall.Request{
			RequestFunctions:  r,
			Method:            r.reqMethod,
			URL:               &heimdall.URL{URL: *r.reqURL},
			ClientIPAddresses: r.requestClientIPs(),
		}
	}

	return r.hmdlReq
}

func (r *RequestContext) requestClientIPs() []string {
	var ips []string

	if forwarded := r.req.Header.Get("Forwarded"); len(forwarded) != 0 {
		values := strings.Split(forwarded, ",")
		ips = make([]string, len(values))

		for idx, val := range values {
			for _, val := range strings.Split(strings.TrimSpace(val), ";") {
				if addr, found := strings.CutPrefix(strings.TrimSpace(val), "for="); found {
					ips[idx] = addr
				}
			}
		}
	}

	if ips == nil {
		if forwardedFor := r.req.Header.Get("X-Forwarded-For"); len(forwardedFor) != 0 {
			ips = slicex.Map(strings.Split(forwardedFor, ","), strings.TrimSpace)
		}
	}

	ips = append(ips, httpx.IPFromHostPort(r.req.RemoteAddr)) // nolint: makezero

	return ips
}

func (r *RequestContext) AddHeaderForUpstream(name, value string) { r.upstreamHeaders.Add(name, value) }
func (r *RequestContext) UpstreamHeaders() http.Header            { return r.upstreamHeaders }
func (r *RequestContext) AddCookieForUpstream(name, value string) { r.upstreamCookies[name] = value }
func (r *RequestContext) UpstreamCookies() map[string]string      { return r.upstreamCookies }
func (r *RequestContext) AppContext() context.Context             { return r.req.Context() }
func (r *RequestContext) SetPipelineError(err error)              { r.err = err }
func (r *RequestContext) PipelineError() error                    { return r.err }
func (r *RequestContext) Signer() heimdall.JWTSigner              { return r.jwtSigner }
func (r *RequestContext) Outputs() heimdall.Outputs {
	if r.outputs == nil {
		r.outputs = make(heimdall.Outputs)
	}

	return r.outputs
}
