package proxy2

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/dadrus/heimdall/internal/handler/request"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x"
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
	timeout         time.Duration
	err             error

	savedBody []byte
}

type factoryFunc func(rw http.ResponseWriter, req *http.Request) request.Context

func (f factoryFunc) Create(rw http.ResponseWriter, req *http.Request) request.Context {
	return f(rw, req)
}

func newRequestContextFactory(signer heimdall.JWTSigner, timeout time.Duration) request.ContextFactory {
	return factoryFunc(func(rw http.ResponseWriter, req *http.Request) request.Context {
		return &requestContext{
			jwtSigner:       signer,
			reqMethod:       extractMethod(req),
			reqURL:          extractURL(req),
			upstreamHeaders: make(http.Header),
			upstreamCookies: make(map[string]string),
			rw:              rw,
			req:             req,
			timeout:         timeout,
		}
	})
}

func (r *requestContext) Header(name string) string { return r.req.Header.Get(name) }

func (r *requestContext) Cookie(name string) string {
	if cookie, err := r.req.Cookie(name); err == nil {
		return cookie.Value
	}

	return ""
}

func (r *requestContext) Headers() map[string]string {
	headers := make(map[string]string, len(r.req.Header))

	for k, v := range r.req.Header {
		headers[k] = strings.Join(v, ",")
	}

	return headers
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
	return &heimdall.Request{RequestFunctions: r, Method: r.reqMethod, URL: r.reqURL, ClientIP: r.requestClientIPs()}
}

func (r *requestContext) requestClientIPs() []string {
	var ips []string

	if forwarded := r.req.Header.Get("Forwarded"); len(forwarded) != 0 {
		values := strings.Split(forwarded, ",")
		ips = make([]string, len(values))

		for idx, val := range values {
			for _, val := range strings.Split(strings.TrimSpace(val), ";") {
				if addr, found := strings.CutPrefix(val, "for="); found {
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

	// nolint: makezero
	ips = append(ips, strings.Split(r.req.RemoteAddr, ":")[0])

	return ips
}

func (r *requestContext) AddHeaderForUpstream(name, value string) { r.upstreamHeaders.Add(name, value) }
func (r *requestContext) AddCookieForUpstream(name, value string) { r.upstreamCookies[name] = value }
func (r *requestContext) AppContext() context.Context             { return r.req.Context() }
func (r *requestContext) SetPipelineError(err error)              { r.err = err }
func (r *requestContext) Signer() heimdall.JWTSigner              { return r.jwtSigner }

func (r *requestContext) Finalize(mut rule.URIMutator) error {
	logger := zerolog.Ctx(r.AppContext())
	logger.Debug().Msg("Finalizing request")

	if r.err != nil {
		return r.err
	}

	targetURL, err := mut.Mutate(r.reqURL)
	if err != nil {
		return err
	}

	logger.Info().
		Str("_method", r.reqMethod).
		Str("_upstream", targetURL.String()).
		Msg("Forwarding request")

	proxy := &httputil.ReverseProxy{
		Transport: otelhttp.NewTransport(
			// non default transport is used here only because of the
			// tlsClientConfig used for test purposes
			httpx.NewTraceRoundTripper(&http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				MaxIdleConns:          100,              //nolint:gomnd
				IdleConnTimeout:       90 * time.Second, //nolint:gomnd
				TLSHandshakeTimeout:   10 * time.Second, //nolint:gomnd
				ExpectContinueTimeout: 1 * time.Second,
				TLSClientConfig:       tlsClientConfig,
				ForceAttemptHTTP2:     true,
			}),
			otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
				return fmt.Sprintf("%s %s %s @%s", r.Proto, r.Method, r.URL.Path, r.URL.Host)
			})),
		Rewrite: r.requestRewriter(targetURL),
	}

	proxy.ServeHTTP(r.rw, r.req)

	return nil
}

func (r *requestContext) requestRewriter(targetURL *url.URL) func(req *httputil.ProxyRequest) {
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

		for k, v := range r.upstreamCookies {
			proxyReq.Out.AddCookie(&http.Cookie{Name: k, Value: v})
		}

		// set headers, which might be relevant for the upstream, if these are present in the original request
		// and have not been dropped
		if val := proxyReq.In.Header.Get("X-Forwarded-Proto"); len(val) != 0 {
			proxyReq.Out.Header.Set("X-Forwarded-Proto", val)
		}

		if val := proxyReq.In.Header.Get("X-Forwarded-Host"); len(val) != 0 {
			proxyReq.Out.Header.Set("X-Forwarded-Host", val)
		}

		// it is safe to reuse these headers here, as these have been already dropped if the source is untrusted
		forwardedForHeaderValue := proxyReq.In.Header.Get("X-Forwarded-For")
		forwardedHeaderValue := proxyReq.In.Header.Get("Forwarded")

		addr := strings.Split(r.req.RemoteAddr, ":")
		clientIP := addr[0]

		// Set the X-Forwarded-For
		if len(forwardedForHeaderValue) != 0 {
			proxyReq.Out.Header.Set("X-Forwarded-For",
				x.IfThenElseExec(len(forwardedForHeaderValue) == 0,
					func() string { return clientIP },
					func() string { return fmt.Sprintf("%s, %s", forwardedForHeaderValue, clientIP) }))
		} else {
			// Set the Forwarded header
			proxyReq.Out.Header.Set("Forwarded",
				x.IfThenElseExec(len(forwardedHeaderValue) == 0,
					func() string {
						return fmt.Sprintf("for=%s;proto=%s", clientIP,
							x.IfThenElse(proxyReq.Out.TLS != nil, "https", "http"))
					},
					func() string {
						return fmt.Sprintf("%s, for=%s;proto=%s", forwardedHeaderValue, clientIP,
							x.IfThenElse(proxyReq.Out.TLS != nil, "https", "http"))
					},
				),
			)
		}
	}
}
