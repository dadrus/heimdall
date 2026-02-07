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
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"

	envoy_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/rs/zerolog"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/contenttype"
	"github.com/dadrus/heimdall/internal/x"
)

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

type RequestContext struct {
	ctx             context.Context // nolint: containedctx
	reqHeaders      map[string]string
	reqRawBody      []byte
	upstreamHeaders http.Header
	upstreamCookies map[string]string
	err             error
	hmdlReq         *heimdall.Request

	// the following properties are created lazy and cached
	savedBody any
	outputs   map[string]any
}

func newRequestContext() *RequestContext {
	rc := &RequestContext{
		upstreamHeaders: make(http.Header, 6),
		upstreamCookies: make(map[string]string, 4),
		outputs:         make(map[string]any, 10),
	}

	rc.hmdlReq = &heimdall.Request{
		RequestFunctions: rc,
		URL:              &heimdall.URL{},
	}

	return rc
}

func (r *RequestContext) Init(ctx context.Context, req *envoy_auth.CheckRequest) {
	var clientIPs []string

	if rmd, ok := metadata.FromIncomingContext(ctx); ok {
		// this header is used by envoyproxy to forward the ip addresses of the hops
		if headerValue := rmd.Get("x-forwarded-for"); len(headerValue) != 0 {
			clientIPs = headerValue
		}
	}

	httpReq := req.GetAttributes().GetRequest().GetHttp()

	r.ctx = ctx
	r.reqHeaders = canonicalizeHeaders(httpReq.GetHeaders())
	r.reqRawBody = httpReq.GetRawBody()
	r.hmdlReq.Method = httpReq.GetMethod()
	r.hmdlReq.URL.URL = url.URL{
		Scheme:   httpReq.GetScheme(),
		Host:     httpReq.GetHost(),
		Path:     httpReq.GetPath(),
		RawQuery: httpReq.GetQuery(),
		Fragment: httpReq.GetFragment(),
	}
	r.hmdlReq.ClientIPAddresses = clientIPs
}

func (r *RequestContext) Reset() {
	r.ctx = nil
	r.reqHeaders = nil
	r.reqRawBody = nil
	r.savedBody = nil
	r.err = nil

	clear(r.upstreamHeaders)
	clear(r.upstreamCookies)
	clear(r.outputs)

	clear(r.hmdlReq.URL.Captures)
	r.hmdlReq.URL.URL = url.URL{}
	r.hmdlReq.Method = ""
	r.hmdlReq.ClientIPAddresses = nil
}

func canonicalizeHeaders(headers map[string]string) map[string]string {
	result := make(map[string]string, len(headers))

	for key, value := range headers {
		result[http.CanonicalHeaderKey(key)] = value
	}

	return result
}

func (r *RequestContext) Request() *heimdall.Request { return r.hmdlReq }
func (r *RequestContext) Headers() map[string]string { return r.reqHeaders }
func (r *RequestContext) Header(name string) string  { return r.reqHeaders[name] }

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
			r.savedBody = string(r.reqRawBody)

			return r.savedBody
		}

		data, err := decoder.Decode(r.reqRawBody)
		if err != nil {
			r.savedBody = string(r.reqRawBody)

			return r.savedBody
		}

		r.savedBody = data
	}

	return r.savedBody
}

func (r *RequestContext) Context() context.Context                { return r.ctx }
func (r *RequestContext) SetPipelineError(err error)              { r.err = err }
func (r *RequestContext) AddHeaderForUpstream(name, value string) { r.upstreamHeaders.Add(name, value) }
func (r *RequestContext) AddCookieForUpstream(name, value string) { r.upstreamCookies[name] = value }
func (r *RequestContext) Outputs() map[string]any                 { return r.outputs }

func (r *RequestContext) Finalize() (*envoy_auth.CheckResponse, error) {
	if r.err != nil {
		return nil, r.err
	}

	zerolog.Ctx(r.ctx).Debug().Msg("Creating response")

	headers := make([]*envoy_core.HeaderValueOption,
		len(r.upstreamHeaders)+x.IfThenElse(len(r.upstreamCookies) == 0, 0, 1))
	hidx := 0

	for k := range r.upstreamHeaders {
		headers[hidx] = &envoy_core.HeaderValueOption{
			Header: &envoy_core.HeaderValue{
				Key:   k,
				Value: strings.Join(r.upstreamHeaders.Values(k), ","),
			},
		}

		hidx++
	}

	if len(r.upstreamCookies) != 0 {
		cookies := make([]string, len(r.upstreamCookies))
		cidx := 0

		for k, v := range r.upstreamCookies {
			cookies[cidx] = k + "=" + v
			cidx++
		}

		headers[hidx] = &envoy_core.HeaderValueOption{
			Header: &envoy_core.HeaderValue{
				Key:   "Cookie",
				Value: strings.Join(cookies, ";"),
			},
		}
	}

	return &envoy_auth.CheckResponse{
		Status: &status.Status{Code: int32(codes.OK)},
		HttpResponse: &envoy_auth.CheckResponse_OkResponse{
			OkResponse: &envoy_auth.OkHttpResponse{Headers: headers},
		},
	}, nil
}
