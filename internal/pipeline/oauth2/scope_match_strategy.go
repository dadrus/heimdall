package oauth2

type ScopeMatchingStrategy interface {
	Match(haystack []string, needle string) bool
}
