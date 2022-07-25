package xfmphu

import (
	"net/url"

	"github.com/gofiber/fiber/v2"

	"github.com/dadrus/heimdall/internal/x"
)

func requestURL(c *fiber.Ctx) *url.URL {
	var (
		proto string
		host  string
		path  string
		query string
	)

	if c.IsProxyTrusted() {
		forwardedURIVal := c.Get(xForwardedURI)
		if len(forwardedURIVal) != 0 {
			forwardedURI, _ := url.Parse(forwardedURIVal)
			proto = forwardedURI.Scheme
			host = forwardedURI.Host
			path = forwardedURI.Path
			query = forwardedURI.Query().Encode()
		}
	}

	if len(path) == 0 {
		path = c.Params("*")
		origReqURL := *c.Request().URI()
		query = string(origReqURL.QueryString())
	}

	return &url.URL{
		Scheme: x.IfThenElseExec(len(proto) != 0,
			func() string { return proto },
			func() string { return c.Protocol() }),
		Host: x.IfThenElseExec(len(host) != 0,
			func() string { return host },
			func() string { return c.Hostname() }),
		Path:     path,
		RawQuery: query,
	}
}
