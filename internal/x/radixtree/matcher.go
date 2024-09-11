package radixtree

// LookupMatcher is used for additional checks while performing the lookup of values in the spanned tree.
type LookupMatcher[V any] interface {
	// Match should return true if the value should be returned by the lookup.
	Match(value V, keys, values []string) bool
}

// The LookupMatcherFunc type is an adapter to allow the use of ordinary functions as match functions.
// If f is a function with the appropriate signature, LookupMatcherFunc(f) is a [LookupMatcher]
// that calls f.
type LookupMatcherFunc[V any] func(value V, keys, values []string) bool

// Match calls f(value).
func (f LookupMatcherFunc[V]) Match(value V, keys, values []string) bool {
	return f(value, keys, values)
}

// ValueMatcher is used for additional checks while deleting of values in the spanned tree.
type ValueMatcher[V any] interface {
	// Match should return true if the value should be deleted from the tree.
	Match(value V) bool
}

// The ValueMatcherFunc type is an adapter to allow the use of ordinary functions as match functions.
// If f is a function with the appropriate signature, ValueMatcherFunc(f) is a [ValueMatcher]
// that calls f.
type ValueMatcherFunc[V any] func(value V) bool

// Match calls f(value).
func (f ValueMatcherFunc[V]) Match(value V) bool {
	return f(value)
}
