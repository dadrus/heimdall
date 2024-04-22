package rules

//go:generate mockery --name PatternMatcher --structname PatternMatcherMock

type PatternMatcher interface {
	Match(pattern string) bool
}
