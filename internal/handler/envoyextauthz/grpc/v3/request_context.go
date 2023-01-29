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

package v3

import (
    "context"
    "fmt"
    "net/http"
    "net/url"
    "strings"

    envoy_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
    envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
    "google.golang.org/genproto/googleapis/rpc/status"

    "github.com/dadrus/heimdall/internal/heimdall"
)

type RequestContext struct {
    ctx             context.Context
    req             *envoy_auth.CheckRequest
    reqURL          *url.URL
    upstreamHeaders http.Header
    upstreamCookies map[string]string
    jwtSigner       heimdall.JWTSigner
    err             error
}

func NewRequestContext(ctx context.Context, req *envoy_auth.CheckRequest, signer heimdall.JWTSigner) *RequestContext {
    return &RequestContext{
        ctx: ctx,
        req: req,
        reqURL: &url.URL{
            Scheme:   req.Attributes.Request.Http.Scheme,
            Host:     req.Attributes.Request.Http.Host,
            Path:     req.Attributes.Request.Http.Path,
            RawQuery: req.Attributes.Request.Http.Query,
            Fragment: req.Attributes.Request.Http.Fragment,
        },
        jwtSigner:       signer,
        upstreamHeaders: make(http.Header),
        upstreamCookies: make(map[string]string),
    }
}

func (s *RequestContext) RequestMethod() string { return s.req.Attributes.Request.Http.Method }
func (s *RequestContext) RequestHeaders() map[string]string {
    return s.req.Attributes.Request.Http.Headers
}
func (s *RequestContext) RequestHeader(name string) string {
    return s.req.Attributes.Request.Http.Headers[name]
}
func (s *RequestContext) RequestCookie(name string) string { return "" }
func (s *RequestContext) RequestQueryParameter(name string) string {
    return s.reqURL.Query().Get(name)
}
func (s *RequestContext) RequestFormParameter(name string) string {
    if s.req.Attributes.Request.Http.Headers["content-type"] != "application/x-www-form-urlencoded" {
        return ""
    }

    values, err := url.ParseQuery(s.req.Attributes.Request.Http.Body)
    if err != nil {
        return ""
    }

    return values.Get(name)
}
func (s *RequestContext) RequestBody() []byte                     { return s.req.Attributes.Request.Http.RawBody }
func (s *RequestContext) AppContext() context.Context             { return s.ctx }
func (s *RequestContext) SetPipelineError(err error)              { s.err = err }
func (s *RequestContext) AddHeaderForUpstream(name, value string) { s.upstreamHeaders.Add(name, value) }
func (s *RequestContext) AddCookieForUpstream(name, value string) { s.upstreamCookies[name] = value }
func (s *RequestContext) Signer() heimdall.JWTSigner              { return s.jwtSigner }
func (s *RequestContext) RequestURL() *url.URL                    { return s.reqURL }
func (s *RequestContext) RequestClientIPs() []string              { return nil }

func (s *RequestContext) Finalize(statusCode int) (*envoy_auth.CheckResponse, error) {
    if s.err != nil {
        return nil, s.err
    }

    var headers []*envoy_core.HeaderValueOption

    for k := range s.upstreamHeaders {
        headers = append(headers, &envoy_core.HeaderValueOption{
            Header: &envoy_core.HeaderValue{
                Key:   k,
                Value: strings.Join(s.upstreamHeaders.Values(k), ","),
            },
        })
    }

    if len(s.upstreamCookies) != 0 {
        var cookies []string

        for k, v := range s.upstreamCookies {
            cookies = append(cookies, fmt.Sprintf("%s=%s", k, v))
        }

        headers = append(headers, &envoy_core.HeaderValueOption{
            Header: &envoy_core.HeaderValue{
                Key:   "Cookie",
                Value: strings.Join(cookies, ";"),
            },
        })
    }

    return &envoy_auth.CheckResponse{
        Status: &status.Status{Code: int32(statusCode)},
        HttpResponse: &envoy_auth.CheckResponse_OkResponse{
            OkResponse: &envoy_auth.OkHttpResponse{Headers: headers},
        },
    }, nil
}
