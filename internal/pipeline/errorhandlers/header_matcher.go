package errorhandlers

import (
	"github.com/dadrus/heimdall/internal/heimdall"
)

type HeaderMatcher map[string][]string

func (hm HeaderMatcher) Match(ctx heimdall.Context) bool {
	for name, valueList := range hm {
		var ok bool
		for _, val := range valueList {
			if val == ctx.RequestHeader(name) {
				ok = true
			}
		}

		if !ok {
			return false
		}
	}

	return true
}
