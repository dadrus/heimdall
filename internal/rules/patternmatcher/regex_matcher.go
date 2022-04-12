package patternmatcher

import (
	"github.com/dlclark/regexp2"
	"github.com/ory/ladon/compiler"
)

type regexpMatcher struct {
	compiled *regexp2.Regexp
}

func newRegexMatcher(pattern string) (*regexpMatcher, error) {
	compiled, err := compiler.CompileRegex(pattern, '<', '>')
	if err != nil {
		return nil, err
	}

	return &regexpMatcher{compiled: compiled}, nil
}

func (m *regexpMatcher) Match(matchAgainst string) bool {
	// ignoring error as it will be set on timeouts, which basically is the same as match miss
	ok, _ := m.compiled.MatchString(matchAgainst)

	return ok
}
