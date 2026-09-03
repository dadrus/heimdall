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
	"iter"
	"maps"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/headerpolicy"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/contenttype"
	"github.com/dadrus/heimdall/internal/x/httpx"
)

var _ pipeline.UpstreamRequest = (*RequestContext)(nil)

type BodySource interface {
	ReadRawBody() ([]byte, error)
}

type Input struct {
	Context    context.Context
	Method     string
	URL        url.URL
	Headers    http.Header
	RemoteAddr string
	Body       BodySource
}

type requestFunctions struct {
	ctx *RequestContext
}

func (f *requestFunctions) Header(name string) string  { return f.ctx.Header(name) }
func (f *requestFunctions) Cookie(name string) string  { return f.ctx.Cookie(name) }
func (f *requestFunctions) Headers() map[string]string { return f.ctx.requestHeaders() }
func (f *requestFunctions) Body() any                  { return f.ctx.Body() }

type RequestContext struct {
	inputHeaders    http.Header
	upstreamHeaders http.Header
	hmdlReq         *pipeline.Request
	ctx             context.Context //nolint: containedctx
	bodySource      BodySource

	// the following properties are created lazy and cached
	err       error
	savedBody any
	rawBody   []byte
	headers   map[string]string
	outputs   pipeline.Results

	connectionSpecificHeaders map[string]struct{}
}

func NewRequestContext() *RequestContext {
	return newRequestContext()
}

func newRequestContext() *RequestContext {
	rc := &RequestContext{
		upstreamHeaders:           make(http.Header, 6),
		outputs:                   make(pipeline.Results, 10),
		headers:                   make(map[string]string, 10),
		connectionSpecificHeaders: make(map[string]struct{}, 5),
	}

	rc.hmdlReq = &pipeline.Request{
		RequestFunctions:  &requestFunctions{ctx: rc},
		URL:               &pipeline.URL{},
		ClientIPAddresses: make([]string, 0, 10),
	}

	return rc
}

func (r *RequestContext) Init(input Input) {
	if input.Headers == nil {
		r.inputHeaders = make(http.Header)
	} else {
		r.inputHeaders = input.Headers
	}
	r.hmdlReq.Method = input.Method
	r.hmdlReq.URL.URL = input.URL
	r.hmdlReq.ClientIPAddresses = requestClientIPs(
		r.hmdlReq.ClientIPAddresses,
		input.Headers,
		input.RemoteAddr,
	)
	r.ctx = input.Context
	r.bodySource = input.Body

	for name := range ConnectionOptions(input.Headers) {
		r.connectionSpecificHeaders[name] = struct{}{}
	}
}

func (r *RequestContext) Reset() {
	r.inputHeaders = nil
	r.bodySource = nil
	r.savedBody = nil
	r.rawBody = nil
	r.err = nil
	r.ctx = nil

	clear(r.outputs)
	clear(r.headers)
	clear(r.upstreamHeaders)
	clear(r.connectionSpecificHeaders)

	r.hmdlReq.URL.URL = url.URL{}
	r.hmdlReq.Method = ""
	r.hmdlReq.ClientIPAddresses = r.hmdlReq.ClientIPAddresses[:0]
	clear(r.hmdlReq.URL.Captures)
}

func (r *RequestContext) Method() string {
	return r.hmdlReq.Method
}

func (r *RequestContext) URL() url.URL { return r.hmdlReq.URL.URL }

func (r *RequestContext) Headers() http.Header {
	headers := r.inputHeaders.Clone()
	headers.Set("Host", r.hmdlReq.URL.Host)

	r.applyHeaderOverlay(headers)

	return headers
}

func (r *RequestContext) AddHeader(name, value string) {
	if !r.isHeaderMutationAllowed(name) {
		return
	}

	if strings.EqualFold(name, "Host") {
		r.upstreamHeaders.Set(name, value)

		return
	}

	r.upstreamHeaders.Add(name, value)
}

func (r *RequestContext) SetHeader(name, value string) {
	if !r.isHeaderMutationAllowed(name) {
		return
	}

	r.upstreamHeaders.Set(name, value)
}

func (r *RequestContext) SetCookie(name, value string) {
	if !r.isHeaderMutationAllowed("Cookie") {
		return
	}

	values := r.inputHeaders.Values("Cookie")
	if overlay, ok := r.upstreamHeaders["Cookie"]; ok {
		values = overlay
	}

	var cookies []*http.Cookie

	if len(values) != 0 {
		var err error

		cookies, err = http.ParseCookie(strings.Join(values, "; "))
		if err != nil {
			zerolog.Ctx(r.Context()).
				Warn().
				Err(err).
				Msg("Ignoring upstream cookie mutation due to malformed Cookie header")

			return
		}
	}

	req := http.Request{
		Header: make(http.Header, 1),
	}

	for _, existing := range cookies {
		if existing.Name != name {
			req.AddCookie(existing)
		}
	}

	req.AddCookie(&http.Cookie{ //nolint:gosec
		Name:  name,
		Value: value,
	})

	r.upstreamHeaders["Cookie"] = req.Header.Values("Cookie")
}

func (r *RequestContext) Header(name string) string {
	key := textproto.CanonicalMIMEHeaderKey(name)
	if key == "Host" {
		return r.hmdlReq.URL.Host
	}

	return strings.Join(r.inputHeaders.Values(key), ",")
}

func (r *RequestContext) Cookie(name string) string {
	req := http.Request{Header: r.inputHeaders}

	if cookie, err := req.Cookie(name); err == nil {
		return cookie.Value
	}

	return ""
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

func (r *RequestContext) SetParent(ctx context.Context) {
	r.ctx = ctx
}

func (r *RequestContext) ConnectionSpecificHeaders() iter.Seq[string] {
	return maps.Keys(r.connectionSpecificHeaders)
}

func (r *RequestContext) isHeaderMutationAllowed(name string) bool {
	name = http.CanonicalHeaderKey(name)
	_, connectionSpecific := r.connectionSpecificHeaders[name]

	var reason string

	switch {
	case headerpolicy.Classify(name) != headerpolicy.Ordinary:
		reason = "header is protected"
	case connectionSpecific:
		reason = "header is connection-specific"
	default:
		return true
	}

	zerolog.Ctx(r.Context()).
		Warn().
		Str("_header", name).
		Str("_reason", reason).
		Msg("Ignoring upstream header mutation")

	return false
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

	if r.bodySource == nil {
		r.rawBody = []byte{}

		return r.rawBody, nil
	}

	body, err := r.bodySource.ReadRawBody()
	if err != nil {
		return nil, err
	}

	if body == nil {
		body = []byte{}
	}

	r.rawBody = body

	return r.rawBody, nil
}

func (r *RequestContext) requestHeaders() map[string]string {
	if len(r.headers) == 0 {
		r.headers["Host"] = r.hmdlReq.URL.Host
		for k, v := range r.inputHeaders {
			r.headers[textproto.CanonicalMIMEHeaderKey(k)] = strings.Join(v, ",")
		}
	}

	return r.headers
}

func requestClientIPs(ips []string, headers http.Header, remoteAddr string) []string {
	res, _ := httpx.IPsFromForwarded(ips, headers.Values("Forwarded"))
	if len(res) == 0 {
		res, _ = httpx.IPsFromXForwardedFor(ips, headers.Values("X-Forwarded-For"))
	}

	if len(res) == 0 {
		res = ips
	}

	res = append(res, httpx.IPFromHostPort(remoteAddr)) // nolint: makezero

	return res
}
