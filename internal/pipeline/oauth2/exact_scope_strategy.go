package oauth2

type ExactScopeStrategyMatcher struct{}

func (ExactScopeStrategyMatcher) Match(haystack []string, needle string) bool {
	for _, this := range haystack {
		if needle == this {
			return true
		}
	}

	return false
}
