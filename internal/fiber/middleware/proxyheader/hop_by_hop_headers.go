package proxyheader

import (
	"net/textproto"
	"strings"

	"github.com/valyala/fasthttp"

	"github.com/dadrus/heimdall/internal/x/stringx"
)

func upgradeType(header *fasthttp.RequestHeader) []byte {
	values := header.Peek("Connection")
	if strings.Contains(stringx.ToString(values), "Upgrade") {
		return header.Peek("Upgrade")
	}

	return nil
}

// Hop-by-hop headers. These are removed when sent to the backend.
// As of RFC 7230, hop-by-hop headers are required to appear in the
// Connection header field. These are the headers defined by the
// obsoleted RFC 2616 (section 13.5.1) and are used for backward
// compatibility.
var hopHeaders = []string{ //nolint:gochecknoglobals
	"Connection",
	"Proxy-Connection", // non-standard but still sent by libcurl and rejected by e.g. google
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",      // canonicalized version of "TE"
	"Trailer", // not Trailers per URL above; https://www.rfc-editor.org/errata_search.php?eid=4522
	"Transfer-Encoding",
	"Upgrade",
}

func removeHopByHopHeaders(header *fasthttp.RequestHeader) {
	values := stringx.ToString(header.Peek("Connection"))

	// RFC 7230, section 6.1: Remove headers listed in the "Connection" header.
	for _, value := range strings.Split(values, ";") {
		for _, sf := range strings.Split(value, ",") {
			if sf = textproto.TrimString(sf); sf != "" {
				header.Del(sf)
			}
		}
	}

	// RFC 2616, section 13.5.1: Remove a set of known hop-by-hop headers.
	// This behavior is superseded by the RFC 7230 Connection header, but
	// preserve it for backwards compatibility.
	for _, f := range hopHeaders {
		header.Del(f)
	}
}
