package oauth2

import (
	"strings"

	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type HierarchicScopeStrategyMatcher []string

func (m HierarchicScopeStrategyMatcher) Match(scopes []string) error {
	for _, required := range m {
		if !m.doMatch(scopes, required) {
			return errorchain.NewWithMessagef(ErrScopeMatch, "required scope %s is missing", required)
		}
	}

	return nil
}

func (m HierarchicScopeStrategyMatcher) doMatch(haystack []string, needle string) bool {
	for _, this := range haystack {
		// foo == foo -> true
		if this == needle {
			return true
		}

		// picture.read > picture -> false (scope picture includes read, write, ...)
		if len(this) > len(needle) {
			continue
		}

		needles := strings.Split(needle, ".")
		haystack := strings.Split(this, ".")
		haystackLen := len(haystack) - 1

		for k, needle := range needles {
			if haystackLen < k {
				return true
			}

			current := haystack[k]
			if current != needle {
				break
			}
		}
	}

	return false
}
