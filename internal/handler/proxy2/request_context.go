package proxy2

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	_interface "github.com/dadrus/heimdall/internal/handler/proxy2/interface"
	"github.com/dadrus/heimdall/internal/handler/proxy2/middlewares/errorhandler"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/httpx"
)

type requestContext struct {
	reqMethod       string
	reqURL          *url.URL
	upstreamHeaders http.Header
	upstreamCookies map[string]string
	jwtSigner       heimdall.JWTSigner
	rw              http.ResponseWriter
	req             *http.Request
	eh              errorhandler.ErrorHandler
	timeout         time.Duration
	err             error
}

type factoryFunc func(rw http.ResponseWriter, req *http.Request) _interface.RequestContext

func (f factoryFunc) Create(rw http.ResponseWriter, req *http.Request) _interface.RequestContext {
	return f(rw, req)
}

func newRequestContextFactory(
	eh errorhandler.ErrorHandler, signer heimdall.JWTSigner, timeout time.Duration,
) _interface.RequestContextFactory {
	return factoryFunc(func(rw http.ResponseWriter, req *http.Request) _interface.RequestContext {
		return &requestContext{
			jwtSigner:       signer,
			reqMethod:       extractMethod(req),
			reqURL:          extractURL(req),
			upstreamHeaders: make(http.Header),
			upstreamCookies: make(map[string]string),
			rw:              rw,
			req:             req,
			eh:              eh,
			timeout:         timeout,
		}
	})
}

func (r *requestContext) Header(name string) string { return r.req.Header.Get(name) }

func (r *requestContext) Cookie(name string) string {
	if cookie, err := r.req.Cookie(name); err == nil {
		return cookie.Raw
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
	return nil
}

func (r *requestContext) Request() *heimdall.Request {
	return &heimdall.Request{
		RequestFunctions: r,
		Method:           r.reqMethod,
		URL:              r.reqURL,
		ClientIP:         r.requestClientIPs(),
	}
}

func (r *requestContext) requestClientIPs() []string {
	if forwarded := r.Header("Forwarded"); len(forwarded) != 0 {
		values := strings.Split(forwarded, ",")
		ips := make([]string, len(values)+1)

		for idx, val := range values {
			for _, val := range strings.Split(val, ";") {
				if addr, found := strings.CutPrefix(val, "for="); found {
					ips[idx] = addr
				}
			}
		}

		ips[len(ips)-1] = strings.Split(r.req.RemoteAddr, ":")[0]

		return ips
	}

	if forwardedFor := r.Header("X-Forwarded-For"); len(forwardedFor) != 0 {
		values := strings.Split(forwardedFor, ",")
		ips := make([]string, len(values)+1)

		copy(ips, values)

		ips[len(ips)-1] = strings.Split(r.req.RemoteAddr, ":")[0]

		return ips
	}

	return nil
}

func (r *requestContext) AddHeaderForUpstream(name, value string) { r.upstreamHeaders.Add(name, value) }
func (r *requestContext) AddCookieForUpstream(name, value string) { r.upstreamCookies[name] = value }
func (r *requestContext) AppContext() context.Context             { return r.req.Context() }
func (r *requestContext) SetPipelineError(err error)              { r.err = err }
func (r *requestContext) Signer() heimdall.JWTSigner              { return r.jwtSigner }

func (r *requestContext) Error(err error) { r.eh.HandleError(r.rw, r.req, err) }

func (r *requestContext) Finalize(targetURL *url.URL) {
	logger := zerolog.Ctx(r.req.Context())
	logger.Debug().Msg("Finalizing request")

	if r.err != nil {
		r.eh.HandleError(r.rw, r.req, r.err)
	}

	logger.Info().
		Str("_method", r.reqMethod).
		Str("_upstream", targetURL.String()).
		Msg("Forwarding request")

	proxy := &httputil.ReverseProxy{
		Transport: otelhttp.NewTransport(
			httpx.NewTraceRoundTripper(http.DefaultTransport),
			otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
				return fmt.Sprintf("%s %s %s @%s", r.Proto, r.Method, r.URL.Path, r.URL.Host)
			})),
		Rewrite: r.requestRewriter(targetURL, maps.Clone(r.req.Header)),
	}

	ctx, cancel := context.WithTimeout(r.req.Context(), r.timeout)
	defer cancel()

	proxy.ServeHTTP(r.rw, r.req.WithContext(ctx))
}

func (r *requestContext) requestRewriter(targetURL *url.URL, origHeader http.Header) func(req *httputil.ProxyRequest) {
	return func(proxyReq *httputil.ProxyRequest) {
		proxyReq.Out.Method = r.reqMethod
		proxyReq.Out.URL = targetURL

		for k := range r.upstreamHeaders {
			proxyReq.Out.Header.Set(k, r.upstreamHeaders.Get(k))
		}

		for k, v := range r.upstreamCookies {
			proxyReq.Out.AddCookie(&http.Cookie{Name: k, Value: v})
		}

		// delete headers, which are useless for the upstream service, before forwarding the request
		proxyReq.Out.Header.Del("X-Forwarded-Method")
		proxyReq.Out.Header.Del("X-Forwarded-Uri")
		proxyReq.Out.Header.Del("X-Forwarded-Path")

		// set headers, which might be relevant for the upstream, if these are present in the original request
		// and have not been dropped
		if val := origHeader.Get("X-Forwarded-Proto"); len(val) != 0 {
			proxyReq.Out.Header.Set("X-Forwarded-Proto", val)
		}

		if val := origHeader.Get("X-Forwarded-Host"); len(val) != 0 {
			proxyReq.Out.Header.Set("X-Forwarded-Host", val)
		}

		// it is safe to reuse these headers here, as these have been already dropped if the source is untrusted
		forwardedForHeaderValue := origHeader.Get("X-Forwarded-For")
		forwardedHeaderValue := origHeader.Get("Forwarded")

		addr := strings.Split(r.req.RemoteAddr, ":")
		clientIP := addr[0]

		// Set the X-Forwarded-For
		proxyReq.Out.Header.Set("X-Forwarded-For",
			x.IfThenElseExec(len(forwardedForHeaderValue) == 0,
				func() string { return clientIP },
				func() string { return fmt.Sprintf("%s, %s", forwardedForHeaderValue, clientIP) }))

		// Set the Forwarded header
		proxyReq.Out.Header.Set("Forwarded",
			x.IfThenElseExec(len(forwardedHeaderValue) == 0,
				func() string {
					return fmt.Sprintf("for=%s;proto=%s", clientIP, proxyReq.Out.Proto)
				},
				func() string {
					return fmt.Sprintf("%s, for=%s;proto=%s", forwardedHeaderValue, clientIP, proxyReq.Out.Proto)
				},
			),
		)
	}
}
