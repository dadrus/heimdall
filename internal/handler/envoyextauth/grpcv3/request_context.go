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

package grpcv3

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	envoy_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/rs/zerolog"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/contenttype"
	"github.com/dadrus/heimdall/internal/x/httpx"
	"github.com/dadrus/heimdall/internal/x/urlx"
)

var _ pipeline.UpstreamRequest = (*RequestContext)(nil)

type contextFactory struct {
	pool *sync.Pool
}

func (cf *contextFactory) Create(ctx context.Context, req *envoy_auth.CheckRequest) *RequestContext {
	rc := cf.pool.Get().(*RequestContext) //nolint: forcetypeassert

	rc.Init(ctx, req)

	return rc
}

func (cf *contextFactory) Destroy(rc *RequestContext) {
	rc.Reset()

	cf.pool.Put(rc)
}

func newContextFactory() *contextFactory {
	return &contextFactory{
		pool: &sync.Pool{New: func() any {
			return newRequestContext()
		}},
	}
}

type requestFunctions struct {
	ctx *RequestContext
}

func (f *requestFunctions) Header(name string) string  { return f.ctx.Header(name) }
func (f *requestFunctions) Cookie(name string) string  { return f.ctx.Cookie(name) }
func (f *requestFunctions) Headers() map[string]string { return f.ctx.reqHeaders }
func (f *requestFunctions) Body() any                  { return f.ctx.Body() }

type RequestContext struct {
	ctx             context.Context // nolint: containedctx
	reqHeaders      map[string]string
	reqBody         []byte
	upstreamHeaders http.Header
	err             error
	hmdlReq         *pipeline.Request

	upstreamViewPrepared bool

	// the following properties are created lazy and cached
	savedBody any
	results   pipeline.Results
}

func newRequestContext() *RequestContext {
	rc := &RequestContext{
		upstreamHeaders: make(http.Header, 6),
		results:         make(pipeline.Results, 10),
	}

	rc.hmdlReq = &pipeline.Request{
		RequestFunctions:  &requestFunctions{ctx: rc},
		URL:               &pipeline.URL{},
		ClientIPAddresses: make([]string, 0, 10),
	}

	return rc
}

func (r *RequestContext) Init(ctx context.Context, req *envoy_auth.CheckRequest) {
	httpReq := req.GetAttributes().GetRequest().GetHttp()

	parsed, err := url.ParseRequestURI(httpReq.GetPath())
	if err != nil {
		parsed = &url.URL{}
	} else {
		parsed.RawPath = urlx.NormalizePath(urlx.EscapedPath(parsed))
		parsed.Path, _ = url.PathUnescape(parsed.RawPath)
	}

	r.ctx = ctx
	r.reqHeaders = canonicalizeHeaders(httpReq.GetHeaders())
	r.reqBody = nil

	if r.reqHeaders["X-Envoy-Auth-Partial-Body"] == "false" {
		if rawBody := httpReq.GetRawBody(); rawBody != nil {
			r.reqBody = rawBody
		} else {
			r.reqBody = []byte(httpReq.GetBody())
		}
	}

	r.hmdlReq.Method = httpReq.GetMethod()
	r.hmdlReq.URL.URL = url.URL{
		Scheme:     httpReq.GetScheme(),
		Host:       strings.ToLower(httpReq.GetHost()),
		RawPath:    parsed.RawPath,
		Path:       parsed.Path,
		RawQuery:   parsed.RawQuery,
		ForceQuery: parsed.ForceQuery,
	}
	r.reqHeaders["Host"] = r.hmdlReq.URL.Host
	r.hmdlReq.ClientIPAddresses = requestClientIPs(
		ctx,
		r.hmdlReq.ClientIPAddresses,
		r.reqHeaders,
	)
}

func requestClientIPs(ctx context.Context, ips []string, headers map[string]string) []string {
	res, _ := httpx.IPsFromForwarded(ips, []string{headers["Forwarded"]})
	if len(res) == 0 {
		res, _ = httpx.IPsFromXForwardedFor(ips, []string{headers["X-Forwarded-For"]})
	}

	if len(res) == 0 {
		res = ips
	}

	if peerInfo, ok := peer.FromContext(ctx); ok && peerInfo.Addr != nil {
		peerIP := httpx.IPFromHostPort(peerInfo.Addr.String())
		if len(peerIP) != 0 {
			res = append(res, peerIP)
		}
	}

	return res
}

func (r *RequestContext) Reset() {
	r.ctx = nil
	r.reqHeaders = nil
	r.reqBody = nil
	r.savedBody = nil
	r.err = nil
	r.upstreamViewPrepared = false

	clear(r.upstreamHeaders)
	clear(r.results)

	clear(r.hmdlReq.URL.Captures)
	r.hmdlReq.URL.URL = url.URL{}
	r.hmdlReq.Method = ""
	r.hmdlReq.ClientIPAddresses = r.hmdlReq.ClientIPAddresses[:0]
}

func canonicalizeHeaders(headers map[string]string) map[string]string {
	result := make(map[string]string, len(headers))

	for key, value := range headers {
		result[http.CanonicalHeaderKey(key)] = value
	}

	return result
}

func (r *RequestContext) Request() *pipeline.Request { return r.hmdlReq }
func (r *RequestContext) PrepareUpstreamView(_ pipeline.UpstreamTarget) {
	r.upstreamViewPrepared = true
}

func (r *RequestContext) Method() string { return r.hmdlReq.Method }

func (r *RequestContext) URL() url.URL { return r.hmdlReq.URL.URL }

func (r *RequestContext) Headers() http.Header {
	headers := make(http.Header, len(r.reqHeaders)+len(r.upstreamHeaders))

	for name, value := range r.reqHeaders {
		if http.CanonicalHeaderKey(name) == "X-Envoy-Auth-Partial-Body" {
			continue
		}

		headers[name] = []string{value}
	}

	r.applyHeaderOverlay(headers)
	headers.Del("X-Envoy-Auth-Partial-Body")

	return headers
}

func (r *RequestContext) AddHeader(name, value string) {
	if strings.EqualFold(name, "Host") {
		r.upstreamHeaders.Set(name, value)

		return
	}

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

func (r *RequestContext) UpstreamRequest() pipeline.UpstreamRequest {
	if !r.upstreamViewPrepared {
		return nil
	}

	return r
}

func (r *RequestContext) RawBody() (io.ReadCloser, error) {
	if len(r.reqBody) == 0 {
		return http.NoBody, nil
	}

	return io.NopCloser(bytes.NewReader(r.reqBody)), nil
}

func (r *RequestContext) Header(name string) string {
	return r.reqHeaders[http.CanonicalHeaderKey(name)]
}

func (r *RequestContext) Cookie(name string) string {
	values, ok := r.reqHeaders["Cookie"]
	if !ok {
		return ""
	}

	for cookie := range strings.SplitSeq(values, ";") {
		if cookieName, cookieValue, ok := strings.Cut(cookie, "="); ok && strings.TrimSpace(cookieName) == name {
			return strings.TrimSpace(cookieValue)
		}
	}

	return ""
}

func (r *RequestContext) Body() any {
	if r.savedBody == nil {
		decoder, err := contenttype.NewDecoder(r.Header("Content-Type"))
		if err != nil {
			r.savedBody = string(r.reqBody)

			return r.savedBody
		}

		data, err := decoder.Decode(r.reqBody)
		if err != nil {
			r.savedBody = string(r.reqBody)

			return r.savedBody
		}

		r.savedBody = data
	}

	return r.savedBody
}

func (r *RequestContext) Context() context.Context  { return r.ctx }
func (r *RequestContext) SetError(err error)        { r.err = err }
func (r *RequestContext) Error() error              { return r.err }
func (r *RequestContext) Outputs() pipeline.Results { return r.results }

func (r *RequestContext) WithParent(ctx context.Context) pipeline.Context {
	r.ctx = ctx

	return r
}

func (r *RequestContext) Finalize() (*envoy_auth.CheckResponse, error) {
	if r.err != nil {
		return nil, r.err
	}

	zerolog.Ctx(r.ctx).Debug().Msg("Creating response")

	headers := make([]*envoy_core.HeaderValueOption, 0, len(r.upstreamHeaders))

	for name, values := range r.upstreamHeaders {
		if http.CanonicalHeaderKey(name) == "X-Envoy-Auth-Partial-Body" {
			continue
		}

		headers = append(headers, &envoy_core.HeaderValueOption{
			Header: &envoy_core.HeaderValue{
				Key:   name,
				Value: strings.Join(values, ","),
			},
		})
	}

	return &envoy_auth.CheckResponse{
		Status: &status.Status{Code: int32(codes.OK)},
		HttpResponse: &envoy_auth.CheckResponse_OkResponse{
			OkResponse: &envoy_auth.OkHttpResponse{
				Headers: headers,
			},
		},
	}, nil
}

func (r *RequestContext) effectiveHeaderValues(name string) []string {
	name = http.CanonicalHeaderKey(name)

	if values, ok := r.upstreamHeaders[name]; ok {
		return values
	}

	if value, ok := r.reqHeaders[name]; ok {
		return []string{value}
	}

	return nil
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
