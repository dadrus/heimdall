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
	"math"
	"net/http"
	"net/textproto"
	"net/url"
	"sort"
	"strings"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/contenttype"
	"github.com/dadrus/heimdall/internal/x/httpx"
)

type RequestContext struct {
	upstreamHeaders http.Header
	upstreamCookies map[string]string
	upstreamHMFs    []pipeline.HTTPMessageFinalizer
	hmdlReq         *pipeline.Request
	req             *http.Request
	ctx             context.Context //nolint: containedctx

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

	rc.hmdlReq = &pipeline.Request{
		RequestFunctions:  rc,
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
	r.err = nil
	r.req = nil
	r.ctx = nil
	r.upstreamHMFs = r.upstreamHMFs[:0]

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

func (r *RequestContext) Headers() map[string]string {
	if len(r.headers) == 0 {
		r.headers["Host"] = r.hmdlReq.URL.Host
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

func (r *RequestContext) HTTPMessage(options ...pipeline.HTTPMessageOption) (*pipeline.HTTPMessage, error) {
	var (
		getBody      func() (io.ReadCloser, error)
		bodySnapshot []byte
	)

	opts := pipeline.NewHTTPMessageOptions(options...)

	switch {
	case r.req.GetBody != nil:
		getBody = r.req.GetBody
	case r.req.Body == nil || r.req.Body == http.NoBody:
		getBody = func() (io.ReadCloser, error) { return http.NoBody, nil }
	default:
		getBody = func() (io.ReadCloser, error) {
			if len(bodySnapshot) != 0 {
				return io.NopCloser(bytes.NewReader(bodySnapshot)), nil
			}

			body, err := readRequestBody(r.req.Body, opts.MaxBodySize)
			if err != nil {
				_ = r.req.Body.Close()

				return nil, err
			}

			if err := r.req.Body.Close(); err != nil {
				return nil, err
			}

			bodySnapshot = body
			r.req.Body = io.NopCloser(bytes.NewReader(bodySnapshot))

			return io.NopCloser(bytes.NewReader(bodySnapshot)), nil
		}
	}

	return &pipeline.HTTPMessage{
		Context:   r.ctx,
		Method:    r.hmdlReq.Method,
		Authority: r.hmdlReq.URL.Host,
		URL:       new(r.hmdlReq.URL.URL),
		Header:    r.req.Header.Clone(),
		Body:      getBody,
	}, nil
}

func readRequestBody(body io.Reader, maxBodySize int64) ([]byte, error) {
	var (
		buf    bytes.Buffer
		reader = body
	)

	if maxBodySize > 0 && maxBodySize < math.MaxInt64 {
		reader = io.LimitReader(body, maxBodySize+1)
	}

	if _, err := buf.ReadFrom(reader); err != nil {
		return nil, err
	}

	if maxBodySize > 0 && int64(buf.Len()) > maxBodySize {
		return nil, pipeline.ErrHTTPMessageBodyTooLarge
	}

	return buf.Bytes(), nil
}

func (r *RequestContext) Request() *pipeline.Request              { return r.hmdlReq }
func (r *RequestContext) AddHeaderForUpstream(name, value string) { r.upstreamHeaders.Add(name, value) }
func (r *RequestContext) UpstreamHeaders() http.Header            { return r.upstreamHeaders }
func (r *RequestContext) AddCookieForUpstream(name, value string) { r.upstreamCookies[name] = value }
func (r *RequestContext) UpstreamCookies() map[string]string      { return r.upstreamCookies }
func (r *RequestContext) AddHTTPMessageFinalizerForUpstream(finalizer pipeline.HTTPMessageFinalizer) {
	r.upstreamHMFs = append(r.upstreamHMFs, finalizer)
}

func (r *RequestContext) HTTPMessageFinalizersForUpstream() []pipeline.HTTPMessageFinalizer {
	return r.upstreamHMFs
}

func (r *RequestContext) Context() context.Context { return r.ctx }
func (r *RequestContext) SetError(err error)       { r.err = err }
func (r *RequestContext) Error() error             { return r.err }
func (r *RequestContext) Outputs() map[string]any  { return r.outputs }

func (r *RequestContext) WithParent(ctx context.Context) pipeline.Context {
	r.ctx = ctx

	return r
}

func CookieHeader(cookies map[string]string) string {
	if len(cookies) == 0 {
		return ""
	}

	names := make([]string, 0, len(cookies))
	for name := range cookies {
		names = append(names, name)
	}

	sort.Strings(names)

	req := http.Request{Header: make(http.Header, 1)}
	for _, name := range names {
		req.AddCookie(&http.Cookie{Name: name, Value: cookies[name]})
	}

	return req.Header.Get("Cookie")
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
