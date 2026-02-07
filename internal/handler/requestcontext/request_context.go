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
)

type RequestContext struct {
	upstreamHeaders http.Header
	upstreamCookies map[string]string
	hmdlReq         *heimdall.Request
	req             *http.Request

	// the following properties are created lazy and cached
	err       error
	savedBody any
	headers   map[string]string
	outputs   map[string]any
}

func New() *RequestContext {
	rc := &RequestContext{
		upstreamHeaders: make(http.Header, 6),
		upstreamCookies: make(map[string]string, 4),
		outputs:         make(map[string]any, 10),
		headers:         make(map[string]string, 10),
	}

	rc.hmdlReq = &heimdall.Request{
		RequestFunctions:  rc,
		URL:               &heimdall.URL{},
		ClientIPAddresses: make([]string, 0, 10),
	}

	return rc
}

func (r *RequestContext) Init(req *http.Request) {
	r.req = req
	r.hmdlReq.Method = extractMethod(req)
	r.hmdlReq.URL.URL = extractURL(req)
	r.hmdlReq.ClientIPAddresses = requestClientIPs(r.hmdlReq.ClientIPAddresses, req)
}

func (r *RequestContext) Reset() {
	r.savedBody = nil
	r.err = nil
	r.req = nil

	clear(r.outputs)
	clear(r.headers)
	clear(r.upstreamCookies)
	clear(r.upstreamHeaders)

	r.hmdlReq.URL.URL = url.URL{}
	r.hmdlReq.Method = ""
	r.hmdlReq.ClientIPAddresses = r.hmdlReq.ClientIPAddresses[:0]
	clear(r.hmdlReq.URL.Captures)
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

func (r *RequestContext) Request() *heimdall.Request              { return r.hmdlReq }
func (r *RequestContext) AddHeaderForUpstream(name, value string) { r.upstreamHeaders.Add(name, value) }
func (r *RequestContext) UpstreamHeaders() http.Header            { return r.upstreamHeaders }
func (r *RequestContext) AddCookieForUpstream(name, value string) { r.upstreamCookies[name] = value }
func (r *RequestContext) UpstreamCookies() map[string]string      { return r.upstreamCookies }
func (r *RequestContext) Context() context.Context                { return r.req.Context() }
func (r *RequestContext) SetError(err error)                      { r.err = err }
func (r *RequestContext) Error() error                            { return r.err }
func (r *RequestContext) Outputs() map[string]any                 { return r.outputs }

func requestClientIPs(ips []string, req *http.Request) []string {
	if forwarded := req.Header.Get("Forwarded"); len(forwarded) != 0 {
		for entry := range strings.SplitSeq(forwarded, ",") {
			for val := range strings.SplitSeq(strings.TrimSpace(entry), ";") {
				if addr, found := strings.CutPrefix(strings.TrimSpace(val), "for="); found {
					ips = append(ips, strings.TrimSpace(addr))
				}
			}
		}
	}

	if ips == nil {
		if forwardedFor := req.Header.Get("X-Forwarded-For"); len(forwardedFor) != 0 {
			for val := range strings.SplitSeq(forwardedFor, ",") {
				ips = append(ips, strings.TrimSpace(val))
			}
		}
	}

	ips = append(ips, httpx.IPFromHostPort(req.RemoteAddr)) // nolint: makezero

	return ips
}
