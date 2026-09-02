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

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/contenttype"
	"github.com/dadrus/heimdall/internal/x/httpx"
)

var _ pipeline.UpstreamRequest = (*RequestContext)(nil)

type requestFunctions struct {
	ctx *RequestContext
}

func (f *requestFunctions) Header(name string) string  { return f.ctx.Header(name) }
func (f *requestFunctions) Cookie(name string) string  { return f.ctx.Cookie(name) }
func (f *requestFunctions) Headers() map[string]string { return f.ctx.requestHeaders() }
func (f *requestFunctions) Body() any                  { return f.ctx.Body() }

type RequestContext struct {
	upstreamHeaders http.Header
	hmdlReq         *pipeline.Request
	req             *http.Request
	ctx             context.Context //nolint: containedctx

	// the following properties are created lazy and cached
	err       error
	savedBody any
	rawBody   []byte
	headers   map[string]string
	outputs   pipeline.Results
}

func (r *RequestContext) UpstreamRequest() pipeline.UpstreamRequest {
	return nil
}

func New() *RequestContext {
	rc := &RequestContext{
		upstreamHeaders: make(http.Header, 6),
		outputs:         make(pipeline.Results, 10),
		headers:         make(map[string]string, 10),
	}

	rc.hmdlReq = &pipeline.Request{
		RequestFunctions:  &requestFunctions{ctx: rc},
		URL:               &pipeline.URL{},
		ClientIPAddresses: make([]string, 0, 10),
	}

	return rc
}

func (r *RequestContext) Init(req *http.Request) {
	r.req = req
	r.hmdlReq.Method = extractMethod(req)
	r.hmdlReq.URL.URL = extractURL(req)
	r.hmdlReq.ClientIPAddresses = requestClientIPs(r.hmdlReq.ClientIPAddresses, req)
	r.ctx = req.Context()
}

func (r *RequestContext) Reset() {
	r.savedBody = nil
	r.rawBody = nil
	r.err = nil
	r.req = nil
	r.ctx = nil

	clear(r.outputs)
	clear(r.headers)
	clear(r.upstreamHeaders)

	r.hmdlReq.URL.URL = url.URL{}
	r.hmdlReq.Method = ""
	r.hmdlReq.ClientIPAddresses = r.hmdlReq.ClientIPAddresses[:0]
	clear(r.hmdlReq.URL.Captures)
}

func (r *RequestContext) Method() string {
	return r.hmdlReq.Method
}

func (r *RequestContext) URL() url.URL {
	result := r.hmdlReq.URL.URL
	result.Host = r.effectiveHost()

	return result
}

func (r *RequestContext) Headers() http.Header {
	headers := r.req.Header.Clone()
	headers.Set("Host", r.hmdlReq.URL.Host)

	r.applyHeaderOverlay(headers)

	return headers
}

func (r *RequestContext) AddHeader(name, value string) {
	r.upstreamHeaders.Add(name, value)
}

func (r *RequestContext) SetHeader(name, value string) {
	r.upstreamHeaders.Set(name, value)
}

func (r *RequestContext) SetCookie(name, value string) {
	req := http.Request{
		Header: make(http.Header, 1),
	}

	if values := r.effectiveHeaderValues("Cookie"); len(values) != 0 {
		req.Header["Cookie"] = values
	}

	cookies := req.Cookies()

	req.Header.Del("Cookie")

	for _, cookie := range cookies {
		if cookie.Name != name {
			req.AddCookie(cookie)
		}
	}

	req.AddCookie(&http.Cookie{Name: name, Value: value}) //nolint:gosec

	r.upstreamHeaders["Cookie"] = req.Header.Values("Cookie")
}

func (r *RequestContext) Header(name string) string {
	key := textproto.CanonicalMIMEHeaderKey(name)
	if key == "Host" {
		return r.hmdlReq.URL.Host
	}

	return strings.Join(r.req.Header.Values(key), ",")
}

func (r *RequestContext) Cookie(name string) string {
	if cookie, err := r.req.Cookie(name); err == nil {
		return cookie.Value
	}

	return ""
}

func (r *RequestContext) requestHeaders() map[string]string {
	if len(r.headers) == 0 {
		r.headers["Host"] = r.hmdlReq.URL.Host
		for k, v := range r.req.Header {
			r.headers[textproto.CanonicalMIMEHeaderKey(k)] = strings.Join(v, ",")
		}
	}

	return r.headers
}

func (r *RequestContext) Body() any {
	if r.savedBody == nil {
		body, err := r.readRawBody()
		if err != nil || len(body) == 0 {
			return ""
		}

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

func (r *RequestContext) RawBody() (io.ReadCloser, error) {
	body, err := r.readRawBody()
	if err != nil {
		return nil, err
	}

	if len(body) == 0 {
		return http.NoBody, nil
	}

	return io.NopCloser(bytes.NewReader(body)), nil
}

func (r *RequestContext) Request() *pipeline.Request   { return r.hmdlReq }
func (r *RequestContext) UpstreamHeaders() http.Header { return r.upstreamHeaders }
func (r *RequestContext) Context() context.Context     { return r.ctx }
func (r *RequestContext) SetError(err error)           { r.err = err }
func (r *RequestContext) Error() error                 { return r.err }
func (r *RequestContext) Outputs() pipeline.Results    { return r.outputs }

func (r *RequestContext) WithParent(ctx context.Context) pipeline.Context {
	r.ctx = ctx

	return r
}

func (r *RequestContext) effectiveHeaderValues(name string) []string {
	name = http.CanonicalHeaderKey(name)

	if values, ok := r.upstreamHeaders[name]; ok {
		return values
	}

	if name == "Host" {
		return []string{r.hmdlReq.URL.Host}
	}

	return r.req.Header[name]
}

func (r *RequestContext) effectiveHost() string {
	return strings.Join(r.effectiveHeaderValues("Host"), ",")
}

func (r *RequestContext) applyHeaderOverlay(headers http.Header) {
	for name, values := range r.upstreamHeaders {
		if values == nil {
			headers.Del(name)

			continue
		}

		headers[name] = append([]string(nil), values...)
	}
}

func (r *RequestContext) readRawBody() ([]byte, error) {
	if r.rawBody != nil {
		return r.rawBody, nil
	}

	if r.req.Body == nil || r.req.Body == http.NoBody {
		r.rawBody = []byte{}

		return r.rawBody, nil
	}

	body, err := io.ReadAll(r.req.Body)
	if err != nil {
		return nil, err
	}

	r.rawBody = body
	_ = r.req.Body.Close()
	r.req.Body = io.NopCloser(bytes.NewReader(body))

	return r.rawBody, nil
}

func requestClientIPs(ips []string, req *http.Request) []string {
	res, _ := httpx.IPsFromForwarded(ips, req.Header.Values("Forwarded"))
	if len(res) == 0 {
		res, _ = httpx.IPsFromXForwardedFor(ips, req.Header.Values("X-Forwarded-For"))
	}

	if len(res) == 0 {
		res = ips
	}

	res = append(res, httpx.IPFromHostPort(req.RemoteAddr)) // nolint: makezero

	return res
}
