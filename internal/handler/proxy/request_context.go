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

package proxy

import (
	"context"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/dadrus/heimdall/internal/handler/requestcontext"
	"github.com/dadrus/heimdall/internal/headerpolicy"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/httpx"
)

var _ pipeline.UpstreamRequest = (*requestContext)(nil)

type requestContext struct {
	*requestcontext.NetHTTPRequestContext

	req *http.Request

	routingURL           url.URL
	upstreamViewPrepared bool
	hasUpstreamTarget    bool
}

func (r *requestContext) Init(req *http.Request) {
	r.req = req

	r.NetHTTPRequestContext.Init(req)
}

func (r *requestContext) Reset() {
	r.req = nil

	r.routingURL = url.URL{}
	r.upstreamViewPrepared = false
	r.hasUpstreamTarget = false

	r.NetHTTPRequestContext.Reset()
}

func (r *requestContext) WithParent(ctx context.Context) pipeline.Context {
	r.SetParent(ctx)

	return r
}

func (r *requestContext) UpstreamRequest() pipeline.UpstreamRequest {
	if !r.upstreamViewPrepared {
		return nil
	}

	return r
}

func (r *requestContext) PrepareUpstreamView(target pipeline.UpstreamTarget) {
	r.upstreamViewPrepared = true
	r.hasUpstreamTarget = target != nil

	requestURL := &r.Request().URL.URL
	r.routingURL = url.URL{
		Scheme:     requestURL.Scheme,
		Path:       requestURL.Path,
		RawPath:    requestURL.RawPath,
		RawQuery:   requestURL.RawQuery,
		ForceQuery: requestURL.ForceQuery,
	}

	r.prepareHeaderSanitization()
	r.prepareForwardedHeaders()

	host := r.req.Host

	if target != nil {
		target.ApplyTo(&r.routingURL)

		if !target.ForwardHostHeader() {
			host = r.routingURL.Host
		}
	}

	r.UpstreamHeaders().Set("Host", host)
}

func (r *requestContext) URL() url.URL { return r.routingURL }

func (r *requestContext) rewriteRequest(proxyReq *httputil.ProxyRequest) {
	proxyReq.Out.Method = r.Method()
	proxyReq.Out.URL = &r.routingURL

	r.applyUpstreamView(proxyReq.Out)
}

func (r *requestContext) prepareHeaderSanitization() {
	for name := range r.ConnectionSpecificHeaders() {
		r.removeHeader(name)
	}

	for name := range r.req.Header {
		if headerpolicy.ShouldSanitizeInput(name) {
			r.removeHeader(name)
		}
	}
}

func (r *requestContext) prepareForwardedHeaders() {
	forwardedHost := r.req.Header.Get("X-Forwarded-Host")
	forwardedProto := r.req.Header.Get("X-Forwarded-Proto")
	proto := x.IfThenElse(r.req.TLS != nil, "https", "http")
	clientIP := httpx.IPFromHostPort(r.req.RemoteAddr)
	clientIPs := r.Request().ClientIPAddresses

	r.UpstreamHeaders().Set("X-Forwarded-For", strings.Join(clientIPs, ", "))
	r.UpstreamHeaders().Set("X-Forwarded-Proto", x.IfThenElse(len(forwardedProto) == 0, proto, forwardedProto))
	r.UpstreamHeaders().Set("X-Forwarded-Host", x.IfThenElse(len(forwardedHost) == 0, r.req.Host, forwardedHost))

	if strings.Contains(clientIP, ":") {
		// IPv6 must be quoted
		clientIP = "\"[" + clientIP + "]\""
	}

	current := strings.Join(r.req.Header.Values("Forwarded"), ", ")
	entry := "for=" + clientIP + ";host=\"" + r.req.Host + "\";proto=" + proto

	r.UpstreamHeaders().Set("Forwarded", x.IfThenElseExec(len(current) == 0,
		func() string { return entry },
		func() string { return current + ", " + entry }))
}

func (r *requestContext) removeHeader(name string) {
	r.UpstreamHeaders()[http.CanonicalHeaderKey(name)] = nil
}

func (r *requestContext) applyHeaderOverlay(headers http.Header) {
	for name, values := range r.UpstreamHeaders() {
		if values == nil {
			headers.Del(name)

			continue
		}

		headers[name] = append([]string(nil), values...)
	}
}

func (r *requestContext) applyUpstreamView(req *http.Request) {
	connection, hasConnection := req.Header["Connection"]
	upgrade, hasUpgrade := req.Header["Upgrade"]
	te, hasTE := req.Header["Te"]

	r.applyHeaderOverlay(req.Header)

	overlay := r.UpstreamHeaders()

	if values, ok := overlay["Connection"]; ok && values == nil && hasConnection {
		req.Header["Connection"] = connection
	}

	if values, ok := overlay["Upgrade"]; ok && values == nil && hasUpgrade {
		req.Header["Upgrade"] = upgrade
	}

	if values, ok := overlay["Te"]; ok && values == nil && hasTE {
		req.Header["Te"] = te
	}

	req.Host = overlay.Get("Host")
	req.Header.Del("Host")
}
