package trustedproxy

import (
	"net"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2/log"
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
				for _, name := range untrustedHeader {
					req.Header.Del(name)
				}
			}

			next.ServeHTTP(rw, req)
		})
	}
}
