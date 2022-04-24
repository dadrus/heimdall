package oauth2

import "strings"

type WildcardScopeStrategyMatcher struct{}

// nolint: cyclop
func (WildcardScopeStrategyMatcher) Match(matchers []string, needle string) bool {
	needleParts := strings.Split(needle, ".")

	for _, matcher := range matchers {
		matcherParts := strings.Split(matcher, ".")

		if len(matcherParts) > len(needleParts) {
			continue
		}

		var noteq bool

		for idx, char := range strings.Split(matcher, ".") {
			// this is the last item and the lengths are different
			if idx == len(matcherParts)-1 && len(matcherParts) != len(needleParts) {
				if char != "*" {
					noteq = true

					break
				}
			}

			if char == "*" && len(needleParts[idx]) > 0 {
				// pass because this satisfies the requirements
				continue
			} else if char != needleParts[idx] {
				noteq = true

				break
			}
		}

		if !noteq {
			return true
		}
	}

	return false
}
