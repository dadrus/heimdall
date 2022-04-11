package errorhandlers

type HeaderMatcher map[string][]string

func (hm HeaderMatcher) Match(headers map[string]string) bool {
	for name, valueList := range hm {
		headerVal, found := headers[name]
		if !found {
			return false
		}

		var ok bool

		for _, val := range valueList {
			if val == headerVal {
				ok = true
			}
		}

		if !ok {
			return false
		}
	}

	return true
}
