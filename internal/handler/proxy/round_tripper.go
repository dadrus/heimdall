// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
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
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ccoveille/go-safecast/v2"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/requestcontext"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/httpx"
)

const grpcContentType = "application/grpc"

var (
	errNativeGRPCOverHTTP        = errors.New("native gRPC request cannot use an http upstream")
	errUpgradeOverH2C            = errors.New("connection upgrade request cannot use an h2c upstream")
	errUnsupportedUpstreamScheme = errors.New("unsupported upstream scheme")
)

type upstreamScheme uint8

const (
	upstreamSchemeUnknown upstreamScheme = iota
	upstreamSchemeHTTP
	upstreamSchemeHTTPS
	upstreamSchemeH2C
)

type transportProfile uint8

const (
	transportProfileNormal transportProfile = iota
	transportProfileHTTP1Only
	transportProfileHTTP2Required
)

var _ http.RoundTripper = (*profileRoundTripper)(nil)

type profileRoundTripper struct {
	normal        *http.Transport
	http1Only     *http.Transport
	http2Required *http.Transport
}

func newProfileRoundTripper(cfg config.ServeConfig, tlsCfg *tls.Config) *profileRoundTripper {
	base := newBaseTransport(cfg, tlsCfg)

	return &profileRoundTripper{
		normal:        newTransportProfile(base, transportProfileNormal),
		http1Only:     newTransportProfile(base, transportProfileHTTP1Only),
		http2Required: newTransportProfile(base, transportProfileHTTP2Required),
	}
}

func (rt *profileRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	invocation := proxyInvocationFrom(req.Context())
	transport, err := rt.transportFor(invocation.request)
	if err != nil {
		if req.Body != nil {
			_ = req.Body.Close()
		}

		return nil, err
	}

	return transport.RoundTrip(req)
}

func (rt *profileRoundTripper) transportFor(rc *requestContext) (*http.Transport, error) {
	switch rc.upstreamScheme {
	case upstreamSchemeHTTP:
		if rc.upgrade {
			return rt.http1Only, nil
		}

		if rc.nativeGRPC {
			return nil, errNativeGRPCOverHTTP
		}

		return rt.normal, nil
	case upstreamSchemeHTTPS:
		if rc.upgrade {
			return rt.http1Only, nil
		}

		if rc.nativeGRPC {
			return rt.http2Required, nil
		}

		return rt.normal, nil
	case upstreamSchemeH2C:
		if rc.upgrade {
			return nil, errUpgradeOverH2C
		}

		return rt.http2Required, nil
	default:
		return nil, errorchain.NewWithMessage(errUnsupportedUpstreamScheme, rc.routingURL.Scheme)
	}
}

func newBaseTransport(cfg config.ServeConfig, tlsCfg *tls.Config) *http.Transport {
	return &http.Transport{
		// tlsClientConfig used for test purposes only
		// must be removed as soon as tls configuration
		// is possible per upstream
		Proxy: http.ProxyFromEnvironment,

		DialContext: (&net.Dialer{
			Timeout:   cfg.Upstream.Connections.DialTimeout,
			KeepAlive: 30 * time.Second, //nolint:mnd
		}).DialContext,

		ResponseHeaderTimeout:  cfg.Upstream.Responses.Headers.ReadTimeout,
		MaxResponseHeaderBytes: safecast.MustConvert[int64](cfg.Upstream.Responses.Headers.MaxSize),

		MaxIdleConns:        cfg.Upstream.Connections.MaxIdle,
		MaxIdleConnsPerHost: cfg.Upstream.Connections.MaxIdlePerHost,
		MaxConnsPerHost:     cfg.Upstream.Connections.MaxPerHost,

		IdleConnTimeout:       cfg.Upstream.Connections.IdleTimeout,
		TLSHandshakeTimeout:   cfg.Upstream.Connections.TLSHandshakeTimeout,
		ExpectContinueTimeout: cfg.Upstream.Requests.ExpectContinueTimeout,

		TLSClientConfig: tlsCfg,
	}
}

func newTransportProfile(base *http.Transport, profile transportProfile) *http.Transport {
	transport := base.Clone()
	transport.Protocols = new(http.Protocols)

	switch profile {
	case transportProfileNormal:
		transport.Protocols.SetHTTP1(true)
		transport.Protocols.SetHTTP2(true)
	case transportProfileHTTP1Only:
		transport.Protocols.SetHTTP1(true)
	case transportProfileHTTP2Required:
		transport.Protocols.SetHTTP2(true)
		transport.Protocols.SetUnencryptedHTTP2(true)
	default:
		panic("unsupported transport profile")
	}

	return transport
}

func upstreamSchemeFrom(scheme string) upstreamScheme {
	switch scheme {
	case "http":
		return upstreamSchemeHTTP
	case "https":
		return upstreamSchemeHTTPS
	case "h2c":
		return upstreamSchemeH2C
	default:
		return upstreamSchemeUnknown
	}
}

func normalizeUpstreamScheme(req *http.Request, scheme upstreamScheme) {
	if scheme == upstreamSchemeH2C {
		req.URL.Scheme = "http"
	}
}

func isUpgradeRequest(req *http.Request) bool {
	if len(req.Header.Get("Upgrade")) == 0 {
		return false
	}

	for option := range requestcontext.ConnectionOptions(req.Header) {
		if option == "Upgrade" {
			return true
		}
	}

	return false
}

func isNativeGRPCContentType(contentType string) bool {
	contentType, _, _ = strings.Cut(strings.TrimSpace(contentType), ";")
	contentType = strings.TrimSpace(contentType)

	if strings.EqualFold(contentType, grpcContentType) {
		return true
	}

	return len(contentType) > len(grpcContentType)+1 &&
		contentType[len(grpcContentType)] == '+' &&
		strings.EqualFold(contentType[:len(grpcContentType)], grpcContentType)
}

func newObservedRoundTripper(rt http.RoundTripper) http.RoundTripper {
	return otelhttp.NewTransport(
		httpx.NewTraceRoundTripper(rt),
		otelhttp.WithSpanNameFormatter(upstreamSpanName),
	)
}

func upstreamSpanName(_ string, req *http.Request) string {
	return req.Proto + " " + req.Method + " " + req.URL.Path + " @" + req.URL.Host
}
