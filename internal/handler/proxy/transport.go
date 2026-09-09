package proxy

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/ccoveille/go-safecast/v2"

	"github.com/dadrus/heimdall/internal/config"
)

func newRoundTripper(
	cfg config.ServeConfig,
	tlsCfg *tls.Config,
) http.RoundTripper {
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

		ForceAttemptHTTP2: true,
		TLSClientConfig:   tlsCfg,
	}
}
