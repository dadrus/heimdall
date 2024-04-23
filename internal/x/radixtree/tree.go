package radixtree

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

var (
	ErrInvalidPath          = errors.New("invalid path")
	ErrNotFound             = errors.New("not found")
	ErrFailedToDelete       = errors.New("failed to delete")
	ErrFailedToUpdate       = errors.New("failed to update")
	ErrConstraintsViolation = errors.New("constraints violation")
)

type (
	ConstraintsFunc[V any] func(oldValues []V, newValue V) bool

	Entry[V any] struct {
		Value      V
		Parameters map[string]string
	}

	Tree[V any] struct {
		path string

		priority int

		// The list of static children to check.
		staticIndices  []byte
		staticChildren []*Tree[V]

		// If none of the above match, check the wildcard children
		wildcardChild *Tree[V]

		// If none of the above match, then we use the catch-all, if applicable.
		catchAllChild *Tree[V]

		isCatchAll bool
		isWildcard bool

		values       []V
		wildcardKeys []string

		canAdd ConstraintsFunc[V]
	}
)

func New[V any](opts ...Option[V]) *Tree[V] {
	root := &Tree[V]{
		canAdd: func(_ []V, _ V) bool { return true },
	}

	for _, opt := range opts {
		opt(root)
	}

	return root
}

func (n *Tree[V]) sortStaticChildren(i int) {
	for i > 0 && n.staticChildren[i].priority > n.staticChildren[i-1].priority {
		n.staticChildren[i], n.staticChildren[i-1] = n.staticChildren[i-1], n.staticChildren[i]
		n.staticIndices[i], n.staticIndices[i-1] = n.staticIndices[i-1], n.staticIndices[i]

		i--
	}
}

func (n *Tree[V]) nextSeparator(path string) int {
	if idx := strings.IndexByte(path, '/'); idx != -1 {
		return idx
	}

	return len(path)
}

//nolint:funlen,gocognit,cyclop
func (n *Tree[V]) addNode(path string, wildcardKeys []string, inStaticToken bool) (*Tree[V], error) {
	if len(path) == 0 {
		// we have a leaf node
		if len(wildcardKeys) != 0 {
			// Ensure the current wildcard keys are the same as the old ones.
			if len(n.wildcardKeys) != 0 && !slices.Equal(n.wildcardKeys, wildcardKeys) {
				return nil, fmt.Errorf("%w: %s is ambigous - wildcard keys differ", ErrInvalidPath, path)
			}

			n.wildcardKeys = wildcardKeys
		}

		return n, nil
	}

	token := path[0]
	nextSlash := strings.IndexByte(path, '/')

	var (
		thisToken string
		tokenEnd  int
		unescaped bool
	)

	switch {
	case token == '/':
		thisToken = "/"
		tokenEnd = 1
	case nextSlash == -1:
		thisToken = path
		tokenEnd = len(path)
	default:
		thisToken = path[0:nextSlash]
		tokenEnd = nextSlash
	}

	remainingPath := path[tokenEnd:]

	if !inStaticToken {
		switch token {
		case '*':
			thisToken = thisToken[1:]

			if nextSlash != -1 {
				return nil, fmt.Errorf("%w: %s has '/' after a free wildcard", ErrInvalidPath, path)
			}

			if n.catchAllChild == nil {
				n.catchAllChild = &Tree[V]{
					path:       thisToken,
					isCatchAll: true,
				}
			}

			if path[1:] != n.catchAllChild.path {
				return nil, fmt.Errorf("%w: free wildcard name in %s doesn't match %s",
					ErrInvalidPath, path, n.catchAllChild.path)
			}

			wildcardKeys = append(wildcardKeys, thisToken)
			n.catchAllChild.wildcardKeys = wildcardKeys

			return n.catchAllChild, nil
		case ':':
			if n.wildcardChild == nil {
				n.wildcardChild = &Tree[V]{path: "wildcard", isWildcard: true}
			}

			return n.wildcardChild.addNode(remainingPath, append(wildcardKeys, thisToken[1:]), false)
		}
	}

	if !inStaticToken &&
		len(thisToken) >= 2 &&
		thisToken[0] == '\\' &&
		(thisToken[1] == '*' || thisToken[1] == ':' || thisToken[1] == '\\') {
		// The token starts with a character escaped by a backslash. Drop the backslash.
		token = thisToken[1]
		thisToken = thisToken[1:]
		unescaped = true
	}

	for i, index := range n.staticIndices {
		if token == index {
			// Yes. Split it based on the common prefix of the existing
			// node and the new one.
			child, prefixSplit := n.splitCommonPrefix(i, thisToken)
			child.priority++

			n.sortStaticChildren(i)

			if unescaped {
				// Account for the removed backslash.
				prefixSplit++
			}

			// Ensure that the rest of this token is not mistaken for a wildcard
			// if a prefix split occurs at a '*' or ':'.
			return child.addNode(path[prefixSplit:], wildcardKeys, token != '/')
		}
	}

	child := &Tree[V]{path: thisToken}

	n.staticIndices = append(n.staticIndices, token)
	n.staticChildren = append(n.staticChildren, child)

	// Ensure that the rest of this token is not mistaken for a wildcard
	// if a prefix split occurs at a '*' or ':'.
	return child.addNode(remainingPath, wildcardKeys, token != '/')
}

//nolint:cyclop
func (n *Tree[V]) delNode(path string, matcher Matcher[V]) bool {
	pathLen := len(path)
	if pathLen == 0 {
		if len(n.values) == 0 {
			return false
		}

		oldSize := len(n.values)
		n.values = slices.DeleteFunc(n.values, matcher.Match)

		return oldSize != len(n.values)
	}

	var (
		nextPath string
		child    *Tree[V]
	)

	token := path[0]

	switch token {
	case ':':
		if n.wildcardChild == nil {
			return false
		}

		child = n.wildcardChild
		nextSeparator := n.nextSeparator(path)
		nextPath = path[nextSeparator:]
	case '*':
		if n.catchAllChild == nil {
			return false
		}

		child = n.catchAllChild
		nextPath = ""
	}

	if child != nil {
		if child.delNode(nextPath, matcher) {
			if len(child.values) == 0 {
				n.deleteChild(child, token)
			}

			return true
		}

		return false
	}

	if len(path) >= 2 &&
		path[0] == '\\' &&
		(path[1] == '*' || path[1] == ':' || path[1] == '\\') {
		// The token starts with a character escaped by a backslash. Drop the backslash.
		token = path[1]
		path = path[1:]
	}

	for i, staticIndex := range n.staticIndices {
		if token == staticIndex {
			child = n.staticChildren[i]
			childPathLen := len(child.path)

			if pathLen >= childPathLen && child.path == path[:childPathLen] &&
				child.delNode(path[childPathLen:], matcher) {
				if len(child.values) == 0 {
					n.deleteChild(child, token)
				}

				return true
			}

			break
		}
	}

	return false
}

//nolint:cyclop
func (n *Tree[V]) deleteChild(child *Tree[V], token uint8) {
	if len(child.staticIndices) == 1 && child.staticIndices[0] != '/' && child.path != "/" {
		if len(child.staticChildren) == 1 {
			grandChild := child.staticChildren[0]
			grandChild.path = child.path + grandChild.path
			*child = *grandChild
		}

		// new leaf created
		if len(child.values) != 0 {
			return
		}
	}

	// Delete the child from the parent only if the child has no children
	if len(child.staticIndices) == 0 && child.wildcardChild == nil && child.catchAllChild == nil {
		switch {
		case child.isWildcard:
			n.wildcardChild = nil
		case child.isCatchAll:
			n.catchAllChild = nil
		default:
			n.delEdge(token)
		}
	}
}

func (n *Tree[V]) delEdge(token byte) {
	for i, index := range n.staticIndices {
		if token == index {
			n.staticChildren = append(n.staticChildren[:i], n.staticChildren[i+1:]...)
			n.staticIndices = append(n.staticIndices[:i], n.staticIndices[i+1:]...)

			return
		}
	}
}

//nolint:funlen,gocognit,cyclop
func (n *Tree[V]) findNode(path string, matcher Matcher[V]) (*Tree[V], int, []string) {
	var (
		found  *Tree[V]
		params []string
		idx    int
		value  V
	)

	pathLen := len(path)
	if pathLen == 0 {
		if len(n.values) == 0 {
			return nil, 0, nil
		}

		for idx, value = range n.values {
			if match := matcher.Match(value); match {
				return n, idx, nil
			}
		}

		return nil, 0, nil
	}

	// First see if this matches a static token.
	firstChar := path[0]
	for i, staticIndex := range n.staticIndices {
		if staticIndex == firstChar {
			child := n.staticChildren[i]
			childPathLen := len(child.path)

			if pathLen >= childPathLen && child.path == path[:childPathLen] {
				nextPath := path[childPathLen:]
				found, idx, params = child.findNode(nextPath, matcher)
			}

			break
		}
	}

	if found != nil {
		return found, idx, params
	}

	if n.wildcardChild != nil { //nolint:nestif
		// Didn't find a static token, so check for a wildcard.
		nextSeparator := n.nextSeparator(path)
		thisToken := path[0:nextSeparator]
		nextToken := path[nextSeparator:]

		if len(thisToken) > 0 { // Don't match on empty tokens.
			found, idx, params = n.wildcardChild.findNode(nextToken, matcher)
			if found != nil {
				if params == nil {
					// we don't expect more than 3 parameters to be defined for a path
					// even 3 is already too much
					params = make([]string, 0, 3) //nolint:gomnd
				}

				return found, idx, append(params, thisToken)
			}
		}
	}

	if n.catchAllChild != nil {
		// Hit the catchall, so just assign the whole remaining path.
		for idx, value = range n.catchAllChild.values {
			if match := matcher.Match(value); match {
				// we don't expect more than 3 parameters to be defined for a path
				// even 3 is already too much
				params = make([]string, 1, 3) //nolint:gomnd
				params[0] = path

				return n.catchAllChild, idx, params
			}
		}

		return nil, 0, nil
	}

	return nil, 0, nil
}

func (n *Tree[V]) splitCommonPrefix(existingNodeIndex int, path string) (*Tree[V], int) {
	childNode := n.staticChildren[existingNodeIndex]

	if strings.HasPrefix(path, childNode.path) {
		// No split needs to be done. Rather, the new path shares the entire
		// prefix with the existing node, so the new node is just a child of
		// the existing one. Or the new path is the same as the existing path,
		// which means that we just move on to the next token. Either way,
		// this return accomplishes that
		return childNode, len(childNode.path)
	}

	// Find the length of the common prefix of the child node and the new path.
	i := commonPrefixLen(childNode.path, path)

	commonPrefix := path[0:i]
	childNode.path = childNode.path[i:]

	// Create a new intermediary node in the place of the existing node, with
	// the existing node as a child.
	newNode := &Tree[V]{
		path:     commonPrefix,
		priority: childNode.priority,
		// Index is the first byte of the non-common part of the path.
		staticIndices:  []byte{childNode.path[0]},
		staticChildren: []*Tree[V]{childNode},
	}
	n.staticChildren[existingNodeIndex] = newNode

	return newNode, i
}

func (n *Tree[V]) Add(path string, value V) error {
	res, err := n.addNode(path, nil, false)
	if err != nil {
		return err
	}

	if !n.canAdd(res.values, value) {
		return fmt.Errorf("%w: %s", ErrConstraintsViolation, path)
	}

	res.values = append(res.values, value)

	return nil
}

func (n *Tree[V]) Find(path string, matcher Matcher[V]) (*Entry[V], error) {
	found, idx, params := n.findNode(path, matcher)
	if found == nil {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
	}

	entry := &Entry[V]{
		Value: found.values[idx],
	}

	if len(params) == 0 {
		return entry, nil
	}

	entry.Parameters = make(map[string]string, len(params))

	for i, param := range params {
		key := found.wildcardKeys[len(params)-1-i]
		if key != "*" {
			entry.Parameters[key] = param
		}
	}

	return entry, nil
}

func (n *Tree[V]) Delete(path string, matcher Matcher[V]) error {
	if !n.delNode(path, matcher) {
		return fmt.Errorf("%w: %s", ErrFailedToDelete, path)
	}

	return nil
}

func (n *Tree[V]) Update(path string, value V, matcher Matcher[V]) error {
	found, idx, _ := n.findNode(path, matcher)
	if found == nil {
		return fmt.Errorf("%w: %s", ErrFailedToUpdate, path)
	}

	found.values[idx] = value

	return nil
}

func (n *Tree[V]) Empty() bool {
	return len(n.values) == 0 && len(n.staticChildren) == 0 && n.wildcardChild == nil && n.catchAllChild == nil
}

func (n *Tree[V]) Clone() *Tree[V] {
	root := &Tree[V]{}

	n.cloneInto(root)

	return root
}

func (n *Tree[V]) cloneInto(out *Tree[V]) {
	*out = *n

	if len(n.wildcardKeys) != 0 {
		out.wildcardKeys = slices.Clone(n.wildcardKeys)
	}

	if len(n.values) != 0 {
		out.values = slices.Clone(n.values)
	}

	if n.catchAllChild != nil {
		out.catchAllChild = &Tree[V]{}
		n.catchAllChild.cloneInto(out.catchAllChild)
	}

	if n.wildcardChild != nil {
		out.wildcardChild = &Tree[V]{}
		n.wildcardChild.cloneInto(out.wildcardChild)
	}

	if len(n.staticChildren) != 0 {
		out.staticIndices = slices.Clone(n.staticIndices)
		out.staticChildren = make([]*Tree[V], len(n.staticChildren))

		for idx, child := range n.staticChildren {
			newChild := &Tree[V]{}

			child.cloneInto(newChild)
			out.staticChildren[idx] = newChild
		}
	}
}
