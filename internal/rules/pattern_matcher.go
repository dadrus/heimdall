package rules

type PatternMatcher interface {
	Match(pattern string) bool
}
