package indextree

// Tree structure to store values associated to paths.
type Tree[V any] pathNode[V]

// Add a value to the tree associated with a path. Paths may contain
// wildcards. Wildcards can be of two types:
//
// - simple wildcard: e.g. /some/:wildcard/path, where a wildcard is
// matched to a single name in the path.
//
// - free wildcard: e.g. /some/path/*wildcard, where a wildcard at the
// end of a path matches anything.
//
// If the path segment has to start with : or *, it must be escaped
// with \ to be not confused with a wildcard.
func (t *Tree[V]) Add(path string, value V) error {
	return (*pathNode[V])(t).add(path[1:], value)
}

// Lookup tries to find value in the tree associated to a path.
// If the found path definition contains wildcards, the values of the
// wildcards are returned in the second argument. While performing a
// lookup the matcher is called to check if the value attached to the
// found node meets the conditions implemented by the matcher. If it
// returns true, then the lookup is done. Otherwise, the lookup
// continues with backtracking from the current tree position.
func (t *Tree[V]) Lookup(path string, m Matcher[V]) (V, map[string]string, error) {
	if path == "" {
		path = "/"
	}

	return (*pathNode[V])(t).find(path[1:], m)
}
