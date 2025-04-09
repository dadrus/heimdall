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
	"fmt"
	"net/http"
	"net/url"
	"strings"

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

type RequestContext struct {
	ctx             context.Context // nolint: containedctx
	ips             []string
	reqMethod       string
	reqHeaders      map[string]string
	reqURL          *url.URL
	reqBody         string
	reqRawBody      []byte
	upstreamHeaders http.Header
	upstreamCookies map[string]string
	err             error

	savedBody any
	outputs   map[string]any
}

func NewRequestContext(ctx context.Context, req *envoy_auth.CheckRequest) *RequestContext {
	var clientIPs []string

	if rmd, ok := metadata.FromIncomingContext(ctx); ok {
		// this header is used by envoyproxy to forward the ip addresses of the hops
		if headerValue := rmd.Get("x-forwarded-for"); len(headerValue) != 0 {
			clientIPs = headerValue
		}
	}

	return &RequestContext{
		ctx:        ctx,
		ips:        clientIPs,
		reqMethod:  req.GetAttributes().GetRequest().GetHttp().GetMethod(),
		reqHeaders: canonicalizeHeaders(req.GetAttributes().GetRequest().GetHttp().GetHeaders()),
		reqURL: &url.URL{
			Scheme:   req.GetAttributes().GetRequest().GetHttp().GetScheme(),
			Host:     req.GetAttributes().GetRequest().GetHttp().GetHost(),
			Path:     req.GetAttributes().GetRequest().GetHttp().GetPath(),
			RawQuery: req.GetAttributes().GetRequest().GetHttp().GetQuery(),
			Fragment: req.GetAttributes().GetRequest().GetHttp().GetFragment(),
		},
		reqBody:         req.GetAttributes().GetRequest().GetHttp().GetBody(),
		reqRawBody:      req.GetAttributes().GetRequest().GetHttp().GetRawBody(),
		upstreamHeaders: make(http.Header),
		upstreamCookies: make(map[string]string),
	}
}

func canonicalizeHeaders(headers map[string]string) map[string]string {
	result := make(map[string]string, len(headers))

	for key, value := range headers {
		result[http.CanonicalHeaderKey(key)] = value
	}

	return result
}

func (r *RequestContext) Request() *heimdall.Request {
	return &heimdall.Request{
		RequestFunctions:  r,
		Method:            r.reqMethod,
		URL:               &heimdall.URL{URL: *r.reqURL},
		ClientIPAddresses: r.ips,
	}
}

func (r *RequestContext) Headers() map[string]string { return r.reqHeaders }
func (r *RequestContext) Header(name string) string  { return r.reqHeaders[name] }

func (r *RequestContext) Cookie(name string) string {
	values, ok := r.reqHeaders["Cookie"]
	if !ok {
		return ""
	}

	for _, cookie := range strings.Split(values, ";") {
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

func (r *RequestContext) Outputs() map[string]any {
	if r.outputs == nil {
		r.outputs = make(map[string]any)
	}

	return r.outputs
}

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
			cookies[cidx] = fmt.Sprintf("%s=%s", k, v)
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
