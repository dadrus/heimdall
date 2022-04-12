package patternmatcher

import "errors"

var ErrUnsupportedPatternMatcher = errors.New("unsupported pattern matcher")

type PatternMatcher interface {
	Match(value string) bool
}

func NewPatternMatcher(typ, pattern string) (PatternMatcher, error) {
	switch typ {
	case "glob":
		return newGlobMatcher(pattern)
	case "regex":
		return newRegexMatcher(pattern)
	default:
		return nil, ErrUnsupportedPatternMatcher
	}
}
