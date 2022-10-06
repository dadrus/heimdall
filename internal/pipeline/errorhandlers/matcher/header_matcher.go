package matcher

import (
	"golang.org/x/exp/slices"
)

type HeaderMatcher map[string][]string

func (hm HeaderMatcher) Match(headers map[string]string) bool {
	for name, valueList := range hm {
		headerVal, found := headers[name]
		if !found || !slices.Contains(valueList, headerVal) {
			return false
		}
	}

	return true
}
