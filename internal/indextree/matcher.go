package indextree

// Matcher is used for additional checks while performing the lookup in the spanned tree
type Matcher[V any] interface {
	// Match should return true if the value should be returned by the lookup. If it returns false, it
	// instructs the lookup to continue with backtracking from the current tree position.
	Match(value V) bool
}

// The MatcherFunc type is an adapter to allow the use of ordinary functions as match functions.
// If f is a function with the appropriate signature, MatcherFunc(f) is a [Matcher]
// that calls f.
type MatcherFunc[V any] func(value V) bool

// Match calls f(value).
func (f MatcherFunc[V]) Match(value V) bool {
	return f(value)
}
