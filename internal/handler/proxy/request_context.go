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
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/requestcontext"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/httpx"
)

type requestContext struct {
	*requestcontext.RequestContext

	rw        http.ResponseWriter
	req       *http.Request
	transport *http.Transport
}

func newContextFactory(
	cfg config.ServeConfig,
	tlsCfg *tls.Config,
) requestcontext.ContextFactory {
	transport := &http.Transport{
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
	}

	return requestcontext.FactoryFunc(func(rw http.ResponseWriter, req *http.Request) requestcontext.Context {
		return &requestContext{
			RequestContext: requestcontext.New(req),
			transport:      transport,
			rw:             rw,
			req:            req,
		}
	})
}

func (r *requestContext) Finalize(upstream rule.Backend) error {
	logger := zerolog.Ctx(r.Context())

	if err := r.PipelineError(); err != nil {
		return err
	}

	if upstream == nil {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration, "No upstream reference defined")
	}

	logger.Info().
		Str("_method", r.Request().Method).
		Str("_upstream", upstream.URL().String()).
		Msg("Forwarding request")

	errHolder := struct{ err error }{}

	proxy := &httputil.ReverseProxy{
		ErrorHandler: func(_ http.ResponseWriter, _ *http.Request, err error) {
			logger.Error().Err(err).Msg("Proxying error")

			errHolder.err = errorchain.NewWithMessage(heimdall.ErrCommunication, "Failed to proxy request").
				CausedBy(err)
		},
		Rewrite: r.rewriteRequest(upstream.URL(), upstream.ForwardHostHeader()),
		Transport: otelhttp.NewTransport(
			httpx.NewTraceRoundTripper(r.transport),
			otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
				return fmt.Sprintf("%s %s %s @%s", r.Proto, r.Method, r.URL.Path, r.URL.Host)
			})),
	}

	proxy.ServeHTTP(r.rw, r.req)

	// set in the proxy error handler above
	return errHolder.err
}

func (r *requestContext) rewriteRequest(targetURL *url.URL, passHostHeader bool) func(req *httputil.ProxyRequest) {
	return func(proxyReq *httputil.ProxyRequest) {
		proxyReq.Out.Method = r.Request().Method
		proxyReq.Out.URL = targetURL
		proxyReq.Out.Host = targetURL.Host

		// delete headers, which are useless for the upstream service, before forwarding the request
		proxyReq.Out.Header.Del("X-Forwarded-Method")
		proxyReq.Out.Header.Del("X-Forwarded-Uri")
		proxyReq.Out.Header.Del("X-Forwarded-Path")

		r.addUpstreamHeader(proxyReq.Out)
		r.addUpstreamCookies(proxyReq.Out)
		r.rewriteForwardedHeader(proxyReq.In, proxyReq.Out)

		if host := proxyReq.Out.Header.Get("Host"); len(host) != 0 {
			proxyReq.Out.Host = host
			proxyReq.Out.Header.Del("Host")
		} else if passHostHeader {
			proxyReq.Out.Host = proxyReq.In.Host
		}
	}
}

func (r *requestContext) rewriteForwardedHeader(in, out *http.Request) {
	// set headers, which might be relevant for the upstream, if these are present in the original request
	// and have not been dropped
	forwardedHost := in.Header.Get("X-Forwarded-Host")
	forwardedProto := in.Header.Get("X-Forwarded-Proto")
	forwardedFor := in.Header.Get("X-Forwarded-For")
	forwarded := in.Header.Get("Forwarded")
	proto := x.IfThenElse(in.TLS != nil, "https", "http")
	clientIP := httpx.IPFromHostPort(in.RemoteAddr)

	out.Header.Set("X-Forwarded-For", x.IfThenElseExec(len(forwardedFor) == 0,
		func() string { return clientIP },
		func() string { return fmt.Sprintf("%s, %s", forwardedFor, clientIP) }))

	out.Header.Set("X-Forwarded-Proto",
		x.IfThenElse(len(forwardedProto) == 0, proto, forwardedProto))

	out.Header.Set("X-Forwarded-Host",
		x.IfThenElse(len(forwardedHost) == 0, in.Host, forwardedHost))

	out.Header.Set("Forwarded", x.IfThenElseExec(len(forwarded) == 0,
		func() string {
			if strings.Contains(clientIP, ":") {
				// IPv6 must be quoted
				clientIP = "\"[" + clientIP + "]\""
			}

			return fmt.Sprintf("for=%s;host=%s;proto=%s",
				clientIP, in.Host, proto)
		},
		func() string {
			if strings.Contains(clientIP, ":") {
				// IPv6 must be quoted
				clientIP = "\"[" + clientIP + "]\""
			}

			return fmt.Sprintf("%s, for=%s;host=%s;proto=%s",
				forwarded, clientIP, in.Host, proto)
		}))
}

func (r *requestContext) addUpstreamCookies(req *http.Request) {
	for k, v := range r.UpstreamCookies() {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
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
