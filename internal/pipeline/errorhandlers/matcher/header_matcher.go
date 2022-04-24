package matcher

import "strings"

type HeaderMatcher map[string][]string

func (hm HeaderMatcher) Match(headers map[string]string) bool {
	for name, valueList := range hm {
		headerVal, found := headers[name]
		if !found {
			return false
		}

		var ok bool

		for _, val := range valueList {
			ok = strings.Contains(headerVal, val)
			if ok {
				break
			}
		}

		if !ok {
			return false
		}
	}

	return true
}
