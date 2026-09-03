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
	"google.golang.org/grpc/peer"

	"github.com/dadrus/heimdall/internal/handler/requestcontext"
	"github.com/dadrus/heimdall/internal/pipeline"
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

type envoyBodySource struct {
	body []byte
}

func (s *envoyBodySource) ReadRawBody() ([]byte, error) {
	return s.body, nil
}

type RequestContext struct {
	*requestcontext.RequestContext

	bodySource envoyBodySource

	upstreamViewPrepared bool
}

func newRequestContext() *RequestContext {
	return &RequestContext{
		RequestContext: requestcontext.NewRequestContext(),
	}
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

	headers := canonicalizeHeaders(httpReq.GetHeaders())

	r.bodySource.body = nil

	if headers.Get("X-Envoy-Auth-Partial-Body") == "false" {
		if rawBody := httpReq.GetRawBody(); rawBody != nil {
			r.bodySource.body = rawBody
		} else {
			r.bodySource.body = []byte(httpReq.GetBody())
		}
	}

	r.RequestContext.Init(requestcontext.Input{
		Context: ctx,
		Method:  httpReq.GetMethod(),
		URL: url.URL{
			Scheme:     httpReq.GetScheme(),
			Host:       strings.ToLower(httpReq.GetHost()),
			RawPath:    parsed.RawPath,
			Path:       parsed.Path,
			RawQuery:   parsed.RawQuery,
			ForceQuery: parsed.ForceQuery,
		},
		Headers:    headers,
		RemoteAddr: peerAddress(ctx),
		Body:       &r.bodySource,
	})
}

func peerAddress(ctx context.Context) string {
	if peerInfo, ok := peer.FromContext(ctx); ok && peerInfo.Addr != nil {
		return peerInfo.Addr.String()
	}

	return ""
}

func (r *RequestContext) Reset() {
	r.bodySource.body = nil
	r.upstreamViewPrepared = false

	r.RequestContext.Reset()
}

func canonicalizeHeaders(headers map[string]string) http.Header {
	result := make(http.Header, len(headers))

	for key, value := range headers {
		result[http.CanonicalHeaderKey(key)] = []string{value}
	}

	return result
}

func (r *RequestContext) PrepareUpstreamView(_ pipeline.UpstreamTarget) {
	r.upstreamViewPrepared = true
}

func (r *RequestContext) UpstreamRequest() pipeline.UpstreamRequest {
	if !r.upstreamViewPrepared {
		return nil
	}

	return r
}

func (r *RequestContext) Headers() http.Header {
	headers := r.RequestContext.Headers()
	headers.Del("X-Envoy-Auth-Partial-Body")

	return headers
}

func (r *RequestContext) WithParent(ctx context.Context) pipeline.Context {
	r.SetParent(ctx)

	return r
}

func (r *RequestContext) Finalize() (*envoy_auth.CheckResponse, error) {
	if err := r.Error(); err != nil {
		return nil, err
	}

	zerolog.Ctx(r.Context()).Debug().Msg("Creating response")

	upstreamHeaders := r.UpstreamHeaders()
	headers := make([]*envoy_core.HeaderValueOption, 0, len(upstreamHeaders))

	for name, values := range upstreamHeaders {
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
