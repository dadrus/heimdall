package config

import (
	"errors"
	"regexp"

	"github.com/gobwas/glob"
)

var (
	ErrNoGlobPatternDefined  = errors.New("no glob pattern defined")
	ErrNoRegexPatternDefined = errors.New("no regex pattern defined")
)

type (
	typedMatcher interface {
		match(pattern string) bool
	}

	globMatcher struct {
		compiled glob.Glob
	}

	regexpMatcher struct {
		compiled *regexp.Regexp
	}

	valueMatcher struct {
		value string
	}
)

func (m *globMatcher) match(value string) bool {
	return m.compiled.Match(value)
}

func (m *regexpMatcher) match(matchAgainst string) bool {
	return m.compiled.MatchString(matchAgainst)
}

func (m *valueMatcher) match(value string) bool { return m.value == value }

func newGlobMatcher(pattern string, separator rune) (typedMatcher, error) {
	if len(pattern) == 0 {
		return nil, ErrNoGlobPatternDefined
	}

	compiled, err := glob.Compile(pattern, separator)
	if err != nil {
		return nil, err
	}

	return &globMatcher{compiled: compiled}, nil
}

func newRegexMatcher(pattern string) (typedMatcher, error) {
	if len(pattern) == 0 {
		return nil, ErrNoRegexPatternDefined
	}

	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	return &regexpMatcher{compiled: compiled}, nil
}

func newValueMatcher(value string) (typedMatcher, error) { return &valueMatcher{value: value}, nil }
