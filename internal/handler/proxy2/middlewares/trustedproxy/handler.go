package trustedproxy

import (
	"net"
	"net/http"
	"strings"

	"github.com/rs/zerolog"
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

func New(logger zerolog.Logger, proxies ...string) func(http.Handler) http.Handler {
	var ipHolders []ipHolder

	for _, ipAddr := range proxies {
		if strings.Contains(ipAddr, "/") {
			_, ipNet, err := net.ParseCIDR(ipAddr)
			if err != nil {
				logger.Warn().Err(err).Msgf("Trusted proxies IP range %q could not be parsed", ipAddr)
			} else {
				ipHolders = append(ipHolders, ipNet)
			}
		} else {
			ipHolders = append(ipHolders, simpleIP(net.ParseIP(ipAddr)))
		}
	}

	trustedProxies := trustedProxySet(ipHolders)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			addr := strings.Split(req.RemoteAddr, ":")
			if !trustedProxies.Contains(net.ParseIP(addr[0])) {
				for _, name := range untrustedHeader {
					req.Header.Del(name)
				}
			}

			next.ServeHTTP(rw, req)
		})
	}
}
