package proxy2

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/textproto"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/request"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/httpx"
	"github.com/dadrus/heimdall/internal/x/slicex"
)

// tlsClientConfig used for test purposes only to
// set the certificate pool for peer certificate verification
// purposes.
var tlsClientConfig *tls.Config // nolint: gochecknoglobals

type requestContext struct {
	reqMethod       string
	reqURL          *url.URL
	upstreamHeaders http.Header
	upstreamCookies map[string]string
	jwtSigner       heimdall.JWTSigner
	rw              http.ResponseWriter
	req             *http.Request
	writeTimeout    time.Duration
	readTimeout     time.Duration
	err             error
	transport       *http.Transport

	// the following properties are created lazy and cached

	savedBody []byte
	hmdlReq   *heimdall.Request
	headers   map[string]string
}

type factoryFunc func(rw http.ResponseWriter, req *http.Request) request.Context

func (f factoryFunc) Create(rw http.ResponseWriter, req *http.Request) request.Context {
	return f(rw, req)
}

func newRequestContextFactory(signer heimdall.JWTSigner, cfg config.ServiceConfig) request.ContextFactory {
	transport := &http.Transport{
		// tlsClientConfig used for test purposes only
		// must be removed as soon as tls configuration
		// is possible per upstream
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second, //nolint:gomnd
			KeepAlive: 30 * time.Second, //nolint:gomnd
		}).DialContext,
		ResponseHeaderTimeout: cfg.Timeout.Read,
		MaxIdleConns:          cfg.ConnectionsLimit.MaxIdle,
		MaxIdleConnsPerHost:   cfg.ConnectionsLimit.MaxIdlePerHost,
		MaxConnsPerHost:       cfg.ConnectionsLimit.MaxPerHost,
		IdleConnTimeout:       cfg.Timeout.Idle,
		TLSHandshakeTimeout:   10 * time.Second, //nolint:gomnd
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       tlsClientConfig,
	}

	return factoryFunc(func(rw http.ResponseWriter, req *http.Request) request.Context {
		return &requestContext{
			jwtSigner:       signer,
			reqMethod:       extractMethod(req),
			reqURL:          extractURL(req),
			upstreamHeaders: make(http.Header),
			upstreamCookies: make(map[string]string),
			rw:              rw,
			req:             req,
			transport:       transport,
			writeTimeout:    cfg.Timeout.Write,
			readTimeout:     cfg.Timeout.Read,
		}
	})
}

func (r *requestContext) Header(name string) string {
	key := textproto.CanonicalMIMEHeaderKey(name)
	if key == "Host" {
		return r.req.Host
	}

	value := r.req.Header[key]
	if len(value) == 0 {
		return ""
	}

	return value[0]
}

func (r *requestContext) Cookie(name string) string {
	if cookie, err := r.req.Cookie(name); err == nil {
		return cookie.Value
	}

	return ""
}

func (r *requestContext) Headers() map[string]string {
	if len(r.headers) == 0 {
		r.headers = make(map[string]string, len(r.req.Header)+1)

		r.headers["Host"] = r.req.Host
		for k, v := range r.req.Header {
			r.headers[textproto.CanonicalMIMEHeaderKey(k)] = strings.Join(v, ",")
		}
	}

	return r.headers
}

func (r *requestContext) Body() []byte {
	if r.req.Body == nil || r.req.Body == http.NoBody {
		return nil
	}

	if r.savedBody == nil {
		// drain body by reading its contents into memory and preserving
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(r.req.Body); err != nil {
			return nil
		}

		if err := r.req.Body.Close(); err != nil {
			return nil
		}

		r.savedBody = buf.Bytes()
		r.req.Body = io.NopCloser(bytes.NewReader(buf.Bytes()))
	}

	return r.savedBody
}

func (r *requestContext) Request() *heimdall.Request {
	if r.hmdlReq == nil {
		r.hmdlReq = &heimdall.Request{
			RequestFunctions: r,
			Method:           r.reqMethod,
			URL:              r.reqURL,
			ClientIP:         r.requestClientIPs(),
		}
	}

	return r.hmdlReq
}

func (r *requestContext) requestClientIPs() []string {
	var ips []string

	if forwarded := r.req.Header.Get("Forwarded"); len(forwarded) != 0 {
		values := strings.Split(forwarded, ",")
		ips = make([]string, len(values))

		for idx, val := range values {
			for _, val := range strings.Split(strings.TrimSpace(val), ";") {
				if addr, found := strings.CutPrefix(strings.TrimSpace(val), "for="); found {
					ips[idx] = addr
				}
			}
		}
	}

	if ips == nil {
		if forwardedFor := r.req.Header.Get("X-Forwarded-For"); len(forwardedFor) != 0 {
			ips = slicex.Map(strings.Split(forwardedFor, ","), strings.TrimSpace)
		}
	}

	ips = append(ips, httpx.IPFromHostPort(r.req.RemoteAddr)) // nolint: makezero

	return ips
}

func (r *requestContext) AddHeaderForUpstream(name, value string) { r.upstreamHeaders.Add(name, value) }
func (r *requestContext) AddCookieForUpstream(name, value string) { r.upstreamCookies[name] = value }
func (r *requestContext) AppContext() context.Context             { return r.req.Context() }
func (r *requestContext) SetPipelineError(err error)              { r.err = err }
func (r *requestContext) Signer() heimdall.JWTSigner              { return r.jwtSigner }

func (r *requestContext) Finalize(upstream rule.Backend) error {
	logger := zerolog.Ctx(r.AppContext())
	logger.Debug().Msg("Finalizing request")

	if r.err != nil {
		return r.err
	}

	if upstream == nil {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration, "No upstream reference defined")
	}

	logger.Info().
		Str("_method", r.reqMethod).
		Str("_upstream", upstream.URL().String()).
		Msg("Forwarding request")

	proxy := &httputil.ReverseProxy{
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
			logger.Error().Err(err).Msg("Proxying error")

			r.err = errorchain.NewWithMessage(heimdall.ErrCommunication, "Failed to proxy request").
				CausedBy(err)
		},
		Rewrite: r.rewriteRequest(upstream.URL()),
		Transport: otelhttp.NewTransport(
			httpx.NewTraceRoundTripper(r.transport),
			otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
				return fmt.Sprintf("%s %s %s @%s", r.Proto, r.Method, r.URL.Path, r.URL.Host)
			})),
	}

	proxy.ServeHTTP(r.rw, r.req)

	// set in the proxy error handler above
	return r.err
}

func (r *requestContext) rewriteRequest(targetURL *url.URL) func(req *httputil.ProxyRequest) {
	return func(proxyReq *httputil.ProxyRequest) {
		proxyReq.Out.Method = r.reqMethod
		proxyReq.Out.URL = targetURL
		proxyReq.Out.Host = targetURL.Host

		// delete headers, which are useless for the upstream service, before forwarding the request
		proxyReq.Out.Header.Del("X-Forwarded-Method")
		proxyReq.Out.Header.Del("X-Forwarded-Uri")
		proxyReq.Out.Header.Del("X-Forwarded-Path")

		for k := range r.upstreamHeaders {
			proxyReq.Out.Header.Set(k, r.upstreamHeaders.Get(k))
		}

		if host := r.upstreamHeaders.Get("Host"); len(host) != 0 {
			proxyReq.Out.Host = host
			proxyReq.Out.Header.Del("Host")
		}

		for k, v := range r.upstreamCookies {
			proxyReq.Out.AddCookie(&http.Cookie{Name: k, Value: v})
		}

		// set headers, which might be relevant for the upstream, if these are present in the original request
		// and have not been dropped
		forwardedHost := proxyReq.In.Header.Get("X-Forwarded-Host")
		forwardedProto := proxyReq.In.Header.Get("X-Forwarded-Proto")
		forwardedFor := proxyReq.In.Header.Get("X-Forwarded-For")
		forwarded := proxyReq.In.Header.Get("Forwarded")
		proto := x.IfThenElse(proxyReq.In.TLS != nil, "https", "http")
		clientIP := httpx.IPFromHostPort(r.req.RemoteAddr)

		if len(forwardedFor) != 0 || len(forwardedProto) != 0 || len(forwardedHost) != 0 {
			proxyReq.Out.Header.Set("X-Forwarded-For", x.IfThenElseExec(len(forwardedFor) == 0,
				func() string { return clientIP },
				func() string { return fmt.Sprintf("%s, %s", forwardedFor, clientIP) }))

			proxyReq.Out.Header.Set("X-Forwarded-Proto",
				x.IfThenElse(len(forwardedProto) == 0, proto, forwardedProto))

			proxyReq.Out.Header.Set("X-Forwarded-Host",
				x.IfThenElse(len(forwardedHost) == 0, proxyReq.In.Host, forwardedHost))
		} else {
			proxyReq.Out.Header.Set("Forwarded", x.IfThenElseExec(len(forwarded) == 0,
				func() string {
					return fmt.Sprintf("for=%s;host=%s;proto=%s",
						clientIP, proxyReq.In.Host, proto)
				},
				func() string {
					return fmt.Sprintf("%s, for=%s;host=%s;proto=%s",
						forwarded, clientIP, proxyReq.In.Host, proto)
				}))
		}
	}
}
