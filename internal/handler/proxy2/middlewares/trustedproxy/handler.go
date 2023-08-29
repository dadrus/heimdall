package trustedproxy

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/gofiber/fiber/v2/log"

	"github.com/dadrus/heimdall/internal/x"
)

var untrustedHeader = []string{ //nolint:gochecknoglobals
	"Forwarded",
	"X-Forwarded-For",
	"X-Forwarded-Proto",
	"X-Forwarded-Host",
	"X-Forwarded-Uri",
	"X-Forwarded-Path",
	"X-Forwarded-Method",
}

type (
	methodKey     struct{}
	requestURLKey struct{}
)

type ipHolder interface {
	Contains(ip net.IP) bool
}

type simpleIP net.IP

func (s simpleIP) Contains(ip net.IP) bool {
	return net.IP(s).Equal(ip)
}

type trustedProxySet []ipHolder

func (tpm trustedProxySet) Contains(ip net.IP) bool {
	for _, proxy := range tpm {
		if proxy.Contains(ip) {
			return true
		}
	}

	return false
}

func New(proxies ...string) func(http.Handler) http.Handler {
	ipHolders := make([]ipHolder, len(proxies))

	for idx, ipAddr := range proxies {
		if strings.Contains(ipAddr, "/") {
			_, ipNet, err := net.ParseCIDR(ipAddr)
			if err != nil {
				log.Warnf("IP range %q could not be parsed: %v", ipAddr, err)
			} else {
				ipHolders[idx] = ipNet
			}
		} else {
			ipHolders[idx] = simpleIP(net.ParseIP(ipAddr))
		}
	}

	trustedProxies := trustedProxySet(ipHolders)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			addr := strings.Split(req.RemoteAddr, ":")
			if !trustedProxies.Contains(net.ParseIP(addr[0])) {
				dropUntrustedHeaders(req)
			}

			method := requestMethod(req)
			reqURL := requestURL(req)

			ctx := context.WithValue(req.Context(), methodKey{}, method)
			ctx = context.WithValue(ctx, requestURLKey{}, reqURL)

			next.ServeHTTP(rw, req.WithContext(ctx))
		})
	}
}

func dropUntrustedHeaders(req *http.Request) {
	for _, name := range untrustedHeader {
		req.Header.Del(name)
	}
}

// RequestMethod returns the HTTP method associated with the ctx. If no method is associated,
// an empty string is returned.
func RequestMethod(ctx context.Context) string {
	var (
		method string
		ok     bool
	)

	if val := ctx.Value(methodKey{}); val != nil {
		method, ok = val.(string)
	}

	return x.IfThenElse(ok, method, "")
}

// RequestURL returns the URL associated with the ctx. If no URL is associated,
// nil is returned.
func RequestURL(ctx context.Context) *url.URL {
	var (
		reqURL *url.URL
		ok     bool
	)

	if val := ctx.Value(requestURLKey{}); val != nil {
		reqURL, ok = val.(*url.URL)
	}

	return x.IfThenElse(ok, reqURL, nil)
}
