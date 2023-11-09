package httpx

import (
	"net"
	"net/http"
)

func LocalAddress(req *http.Request) string {
	localAddr := "unknown"
	if addr, ok := req.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		localAddr = addr.String()
	}

	return localAddr
}
