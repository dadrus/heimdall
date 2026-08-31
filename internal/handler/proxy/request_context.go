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
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/requestcontext"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/httpx"
)

var _ pipeline.UpstreamRequest = (*requestContext)(nil)

type contextFactory struct {
	roundTripper http.RoundTripper
	pool         *sync.Pool
}

func (cf *contextFactory) Create(rw http.ResponseWriter, req *http.Request) requestcontext.Context {
	rc := cf.pool.Get().(*requestContext) //nolint: forcetypeassert

	rc.Init(rw, req, cf.roundTripper)

	return rc
}

func (cf *contextFactory) Destroy(ctx requestcontext.Context) {
	rc := ctx.(*requestContext) //nolint: forcetypeassert

	rc.Reset()

	cf.pool.Put(rc)
}

func newContextFactory(
	cfg config.ServeConfig,
	tlsCfg *tls.Config,
) requestcontext.ContextFactory {
	return &contextFactory{
		roundTripper: &http.Transport{
			// tlsClientConfig used for test purposes only
			// must be removed as soon as tls configuration
			// is possible per upstream
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second, //nolint:mnd
				KeepAlive: 30 * time.Second, //nolint:mnd
			}).DialContext,
			ResponseHeaderTimeout: cfg.Timeout.Read,
			MaxIdleConns:          cfg.ConnectionsLimit.MaxIdle,
			MaxIdleConnsPerHost:   cfg.ConnectionsLimit.MaxIdlePerHost,
			MaxConnsPerHost:       cfg.ConnectionsLimit.MaxPerHost,
			IdleConnTimeout:       cfg.Timeout.Idle,
			TLSHandshakeTimeout:   10 * time.Second, //nolint:mnd
			ExpectContinueTimeout: 1 * time.Second,
			ForceAttemptHTTP2:     true,
			TLSClientConfig:       tlsCfg,
		},
		pool: &sync.Pool{New: func() any {
			return &requestContext{
				RequestContext: requestcontext.New(),
			}
		}},
	}
}

type requestContext struct {
	*requestcontext.RequestContext

	rw  http.ResponseWriter
	req *http.Request
	rt  http.RoundTripper

	routingURL            url.URL
	authority             string
	replacedHeaders       http.Header
	forwardedHeader       string
	xForwardedForHeader   string
	xForwardedHostHeader  string
	xForwardedProtoHeader string
	upstreamPrepared      bool
	hasUpstreamTarget     bool
}

var hopByHopHeaders = [...]string{ //nolint:gochecknoglobals
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func (r *requestContext) Init(rw http.ResponseWriter, req *http.Request, rt http.RoundTripper) {
	r.rw = rw
	r.rt = rt
	r.req = req

	r.RequestContext.Init(req)
}

func (r *requestContext) Reset() {
	r.rw = nil
	r.rt = nil
	r.req = nil

	r.routingURL = url.URL{}
	r.authority = ""
	r.replacedHeaders = nil
	r.forwardedHeader = ""
	r.xForwardedForHeader = ""
	r.xForwardedHostHeader = ""
	r.xForwardedProtoHeader = ""
	r.upstreamPrepared = false
	r.hasUpstreamTarget = false

	r.RequestContext.Reset()
}

func (r *requestContext) UpstreamRequest() pipeline.UpstreamRequest {
	if !r.upstreamPrepared {
		return nil
	}

	return r
}

func (r *requestContext) PrepareUpstreamRequest(target pipeline.UpstreamTarget) {
	r.upstreamPrepared = true
	r.hasUpstreamTarget = target != nil

	requestURL := &r.Request().URL.URL
	r.routingURL = url.URL{
		Scheme:     requestURL.Scheme,
		Path:       requestURL.Path,
		RawPath:    requestURL.RawPath,
		RawQuery:   requestURL.RawQuery,
		ForceQuery: requestURL.ForceQuery,
	}

	r.authority = r.req.Host
	r.prepareForwardedHeaders()

	if target == nil {
		return
	}

	target.ApplyTo(&r.routingURL)

	if !target.ForwardHostHeader() {
		r.authority = r.routingURL.Host
	}
}

func (r *requestContext) Finalize() error {
	logger := zerolog.Ctx(r.Context())

	if err := r.Error(); err != nil {
		return err
	}

	if !r.hasUpstreamTarget {
		return errorchain.NewWithMessage(pipeline.ErrConfiguration, "No upstream reference defined")
	}

	logger.Info().
		Str("_method", r.Request().Method).
		Str("_upstream", r.routingURL.String()).
		Msg("Forwarding request")

	errHolder := struct{ err error }{}

	proxy := &httputil.ReverseProxy{
		ErrorHandler: func(_ http.ResponseWriter, _ *http.Request, err error) {
			logger.Error().Err(err).Msg("Proxying error")

			errHolder.err = errorchain.NewWithMessage(pipeline.ErrCommunication, "Failed to proxy request").
				CausedBy(err)
		},
		Rewrite: r.rewriteRequest,
		Transport: otelhttp.NewTransport(
			httpx.NewTraceRoundTripper(r.rt),
			otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
				return r.Proto + " " + r.Method + " " + r.URL.Path + " @" + r.URL.Host
			})),
	}

	proxy.ServeHTTP(r.rw, r.req)

	// set in the proxy error handler above
	return errHolder.err
}

func (r *requestContext) Method() string    { return r.Request().Method }
func (r *requestContext) Authority() string { return r.authority }

func (r *requestContext) URL() url.URL {
	result := r.routingURL
	result.Host = r.authority

	return result
}

func (r *requestContext) AddHeader(name, value string) {
	if http.CanonicalHeaderKey(name) == "Host" {
		r.authority = value

		return
	}

	r.AddHeaderForUpstream(name, value)
}

func (r *requestContext) SetCookie(name, value string) {
	r.AddCookieForUpstream(name, value)
}

func (r *requestContext) HeaderSnapshot() http.Header {
	var headers http.Header

	if r.replacedHeaders != nil {
		headers = r.replacedHeaders.Clone()
	} else {
		headers = r.req.Header.Clone()

		removeHopByHopHeaders(headers)
		r.applyPreparedHeaders(headers)
	}

	req := http.Request{
		Header: headers,
	}

	r.addUpstreamHeader(&req)
	r.addUpstreamCookies(&req)

	req.Header.Del("Host")

	return req.Header
}

func (r *requestContext) ReplaceHeaders(headers http.Header) {
	r.replacedHeaders = headers

	if r.replacedHeaders == nil {
		r.replacedHeaders = make(http.Header)
	}

	r.replacedHeaders.Del("Host")

	clear(r.UpstreamHeaders())
	clear(r.UpstreamCookies())
}

func (r *requestContext) rewriteRequest(proxyReq *httputil.ProxyRequest) {
	proxyReq.Out.Method = r.Method()
	proxyReq.Out.URL = &r.routingURL
	proxyReq.Out.Host = r.authority

	if r.replacedHeaders != nil {
		r.replaceRequestHeaders(proxyReq.Out)
	} else {
		r.applyPreparedHeaders(proxyReq.Out.Header)
	}

	r.addUpstreamHeader(proxyReq.Out)
	r.addUpstreamCookies(proxyReq.Out)

	if host := proxyReq.Out.Header.Get("Host"); len(host) != 0 {
		proxyReq.Out.Host = host
		proxyReq.Out.Header.Del("Host")
	}
}

func (r *requestContext) prepareForwardedHeaders() {
	forwardedHost := r.req.Header.Get("X-Forwarded-Host")
	forwardedProto := r.req.Header.Get("X-Forwarded-Proto")
	proto := x.IfThenElse(r.req.TLS != nil, "https", "http")
	clientIP := httpx.IPFromHostPort(r.req.RemoteAddr)
	clientIPs := r.Request().ClientIPAddresses

	r.xForwardedForHeader = strings.Join(clientIPs, ", ")
	r.xForwardedProtoHeader = x.IfThenElse(len(forwardedProto) == 0, proto, forwardedProto)
	r.xForwardedHostHeader = x.IfThenElse(len(forwardedHost) == 0, r.req.Host, forwardedHost)

	if strings.Contains(clientIP, ":") {
		// IPv6 must be quoted
		clientIP = "\"[" + clientIP + "]\""
	}

	current := strings.Join(r.req.Header.Values("Forwarded"), ", ")
	entry := "for=" + clientIP + ";host=\"" + r.req.Host + "\";proto=" + proto

	r.forwardedHeader = x.IfThenElseExec(len(current) == 0,
		func() string { return entry },
		func() string { return current + ", " + entry })
}

func (r *requestContext) applyPreparedHeaders(headers http.Header) {
	// delete headers, which are useless for the upstream service, before forwarding the request
	headers.Del("X-Forwarded-Method")
	headers.Del("X-Forwarded-Uri")
	headers.Del("X-Forwarded-Path")

	headers.Set("Forwarded", r.forwardedHeader)
	headers.Set("X-Forwarded-For", r.xForwardedForHeader)
	headers.Set("X-Forwarded-Host", r.xForwardedHostHeader)
	headers.Set("X-Forwarded-Proto", r.xForwardedProtoHeader)
}

func (r *requestContext) replaceRequestHeaders(req *http.Request) {
	connection, hasConnection := req.Header["Connection"]
	upgrade, hasUpgrade := req.Header["Upgrade"]
	te, hasTE := req.Header["Te"]

	req.Header = r.replacedHeaders.Clone()

	_, connectionReplaced := req.Header["Connection"]
	_, upgradeReplaced := req.Header["Upgrade"]

	if !connectionReplaced && !upgradeReplaced {
		if hasConnection {
			req.Header["Connection"] = connection
		}

		if hasUpgrade {
			req.Header["Upgrade"] = upgrade
		}
	}

	if _, replaced := req.Header["Te"]; !replaced && hasTE {
		req.Header["Te"] = te
	}
}

func removeHopByHopHeaders(headers http.Header) {
	for _, value := range headers.Values("Connection") {
		for name := range strings.SplitSeq(value, ",") {
			name = strings.TrimSpace(name)

			if len(name) != 0 {
				headers.Del(name)
			}
		}
	}

	for _, name := range hopByHopHeaders {
		headers.Del(name)
	}
}

func (r *requestContext) addUpstreamCookies(req *http.Request) {
	for k, v := range r.UpstreamCookies() {
		req.AddCookie(&http.Cookie{Name: k, Value: v}) //nolint:gosec
	}
}

func (r *requestContext) addUpstreamHeader(req *http.Request) {
	// delete those headers which are set by heimdall first
	// we do this to prevent spoofing
	uh := r.UpstreamHeaders()
	for name := range uh {
		req.Header.Del(name)
	}

	// add them now
	for name, values := range uh {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
}
