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

var hopByHopHeaders = [...]string{ //nolint: gochecknoglobals
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
				Timeout:   30 * time.Second, //nolint: mnd
				KeepAlive: 30 * time.Second, //nolint: mnd
			}).DialContext,
			ResponseHeaderTimeout: cfg.Timeout.Read,
			MaxIdleConns:          cfg.ConnectionsLimit.MaxIdle,
			MaxIdleConnsPerHost:   cfg.ConnectionsLimit.MaxIdlePerHost,
			MaxConnsPerHost:       cfg.ConnectionsLimit.MaxPerHost,
			IdleConnTimeout:       cfg.Timeout.Idle,
			TLSHandshakeTimeout:   10 * time.Second, //nolint: mnd
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

	routingURL           url.URL
	upstreamViewPrepared bool
	hasUpstreamTarget    bool
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
	r.upstreamViewPrepared = false
	r.hasUpstreamTarget = false

	r.RequestContext.Reset()
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

	r.SetHeader("Host", host)
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

func (r *requestContext) URL() url.URL {
	result := r.routingURL
	result.Host = r.RequestContext.URL().Host

	return result
}

func (r *requestContext) rewriteRequest(proxyReq *httputil.ProxyRequest) {
	proxyReq.Out.Method = r.Method()
	proxyReq.Out.URL = &r.routingURL

	r.applyUpstreamView(proxyReq.Out)
}

func (r *requestContext) prepareHeaderSanitization() {
	for _, value := range r.req.Header.Values("Connection") {
		for name := range strings.SplitSeq(value, ",") {
			name = strings.TrimSpace(name)

			if len(name) != 0 {
				r.removeHeader(name)
			}
		}
	}

	for _, name := range hopByHopHeaders {
		r.removeHeader(name)
	}

	r.removeHeader("X-Forwarded-Method")
	r.removeHeader("X-Forwarded-Uri")
	r.removeHeader("X-Forwarded-Path")
}

func (r *requestContext) prepareForwardedHeaders() {
	forwardedHost := r.req.Header.Get("X-Forwarded-Host")
	forwardedProto := r.req.Header.Get("X-Forwarded-Proto")
	proto := x.IfThenElse(r.req.TLS != nil, "https", "http")
	clientIP := httpx.IPFromHostPort(r.req.RemoteAddr)
	clientIPs := r.Request().ClientIPAddresses

	r.SetHeader("X-Forwarded-For", strings.Join(clientIPs, ", "))
	r.SetHeader("X-Forwarded-Proto", x.IfThenElse(len(forwardedProto) == 0, proto, forwardedProto))
	r.SetHeader("X-Forwarded-Host", x.IfThenElse(len(forwardedHost) == 0, r.req.Host, forwardedHost))

	if strings.Contains(clientIP, ":") {
		// IPv6 must be quoted
		clientIP = "\"[" + clientIP + "]\""
	}

	current := strings.Join(r.req.Header.Values("Forwarded"), ", ")
	entry := "for=" + clientIP + ";host=\"" + r.req.Host + "\";proto=" + proto

	r.SetHeader("Forwarded", x.IfThenElseExec(len(current) == 0,
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

	req.Host = r.RequestContext.URL().Host
	req.Header.Del("Host")
}
