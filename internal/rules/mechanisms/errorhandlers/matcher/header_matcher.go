package matcher

import (
	"strings"
)

type HeaderMatcher map[string][]string

func (hm HeaderMatcher) Match(headers map[string]string) bool {
	for name, valueList := range hm {
		headerVal, found := headers[name]
		if found {
			for _, val := range valueList {
				if strings.Contains(headerVal, val) {
					return true
				}
			}
		}
	}

	return false
}
