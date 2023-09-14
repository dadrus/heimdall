package httpx

import "net"

func IPFromHostPort(hp string) string {
	host, _, err := net.SplitHostPort(hp)
	if err != nil {
		return ""
	}

	if len(host) > 0 && host[0] == '[' {
		return host[1 : len(host)-1]
	}

	return host
}
