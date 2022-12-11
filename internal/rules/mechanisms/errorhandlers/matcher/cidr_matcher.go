package matcher

import (
	"net"

	"github.com/yl2chen/cidranger"
)

func NewCIDRMatcher(cidrs []string) (*CIDRMatcher, error) {
	ranger := cidranger.NewPCTrieRanger()

	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}

		if err := ranger.Insert(cidranger.NewBasicRangerEntry(*ipNet)); err != nil {
			return nil, err
		}
	}

	return &CIDRMatcher{r: ranger}, nil
}

type CIDRMatcher struct {
	r cidranger.Ranger
}

func (c *CIDRMatcher) Match(ips ...string) bool {
	for _, ip := range ips {
		ok, _ := c.r.Contains(net.ParseIP(ip))
		if ok {
			return true
		}
	}

	return false
}
