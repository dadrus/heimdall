package errorhandlers

import (
	"net"

	"github.com/yl2chen/cidranger"

	"github.com/dadrus/heimdall/internal/heimdall"
)

type CIDRMatcher struct {
	r cidranger.Ranger
}

func (c *CIDRMatcher) Match(ctx heimdall.Context) bool {
	for _, ip := range ctx.RequestClientIPs() {
		ok, _ := c.r.Contains(net.ParseIP(ip))
		if ok {
			return true
		}
	}

	return false
}
