package oauth2

import "github.com/dadrus/heimdall/internal/x/errorchain"

type ExactScopeStrategyMatcher []string

func (m ExactScopeStrategyMatcher) Match(scopes []string) error {
	for _, required := range m {
		if !m.doMatch(scopes, required) {
			return errorchain.NewWithMessagef(ErrClaimsNotValid, "required scope %s is missing", required)
		}
	}

	return nil
}

func (m ExactScopeStrategyMatcher) doMatch(haystack []string, needle string) bool {
	for _, this := range haystack {
		if needle == this {
			return true
		}
	}

	return false
}
