package xforwarded

import (
	"net/url"

	"github.com/gofiber/fiber/v2"

	"github.com/dadrus/heimdall/internal/x"
)

func requestURL(c *fiber.Ctx) *url.URL {
	var (
		path   string
		query  string
		scheme string
	)

	if c.IsProxyTrusted() {
		forwardedURIVal := c.Get(xForwardedURI)
		if len(forwardedURIVal) != 0 {
			forwardedURI, _ := url.Parse(forwardedURIVal)
			path = forwardedURI.Path
			query = forwardedURI.Query().Encode()
		}
	}

	if len(path) == 0 {
		path = c.Params("*")
		origReqURL := *c.Request().URI()
		query = string(origReqURL.QueryString())
	}

	if c.IsProxyTrusted() {
		scheme = c.Get(xForwardedProto)
	}

	return &url.URL{
		Scheme:   x.OrDefault(scheme, c.Protocol()),
		Host:     c.Hostname(),
		Path:     path,
		RawQuery: query,
	}
}
