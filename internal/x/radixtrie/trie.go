// Copyright 2022-2025 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package radixtrie

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unsafe"
)

var (
	ErrInvalidPath          = errors.New("invalid path")
	ErrInvalidHost          = errors.New("invalid host")
	ErrNotFound             = errors.New("not found")
	ErrFailedToDelete       = errors.New("failed to delete")
	ErrConstraintsViolation = errors.New("constraints violation")
)

type (
	ConstraintsFunc[V any]  func(oldValues []V, newValue V) bool
	CanBacktrackFunc[V any] func(values []V) bool

	Entry[V any] struct {
		Value      V
		Parameters map[string]string
	}

	Trie[V any] struct {
		token string

		priority int

		// The list of static children to check.
		staticIndices  []byte
		staticChildren []*Trie[V]

		// If none of the above match, check the wildcard children
		wildcardChild *Trie[V]

		// If none of the above match, then we use the catch-all, if applicable.
		catchAllChild *Trie[V]

		isCatchAll bool
		isWildcard bool
		isHostNode bool

		values       []V
		wildcardKeys []string

		// global options
		canAdd ConstraintsFunc[V]

		// node local options
		canBacktrack CanBacktrackFunc[V]
	}

	lookupStrategy[V any] interface {
		lookupNodes(trie *Trie[V], hostPattern, pathPattern string) ([]*Trie[V], error)
	}

	lookupOpts[V any] struct {
		ls lookupStrategy[V]
	}
)

func New[V any](opts ...Option[V]) *Trie[V] {
	root := &Trie[V]{
		canAdd:       func(_ []V, _ V) bool { return true },
		canBacktrack: func(_ []V) bool { return true },
		isHostNode:   true,
	}

	for _, opt := range opts {
		opt(root)
	}

	return root
}

func (t *Trie[V]) sortStaticChildren(i int) {
	for i > 0 && t.staticChildren[i].priority > t.staticChildren[i-1].priority {
		t.staticChildren[i], t.staticChildren[i-1] = t.staticChildren[i-1], t.staticChildren[i]
		t.staticIndices[i], t.staticIndices[i-1] = t.staticIndices[i-1], t.staticIndices[i]

		i--
	}
}

func (t *Trie[V]) nextSeparator(token string, separator byte) int {
	if idx := strings.IndexByte(token, separator); idx != -1 {
		return idx
	}

	return len(token)
}

//nolint:funlen,gocognit,cyclop,gocyclo
func (t *Trie[V]) addNode(
	hostPattern, pathPattern string,
	wildcardKeys []string,
	inStaticToken bool,
) (*Trie[V], error) {
	// Determine which part we're processing and get the appropriate string and separator
	var (
		tokens     string
		separator  byte
		isHostPart bool

		thisToken string
		tokenEnd  int
		unescaped bool
	)

	if len(hostPattern) != 0 {
		tokens = hostPattern
		separator = '.'
		isHostPart = true
	} else {
		tokens = pathPattern
		separator = '/'
		isHostPart = false
	}

	if len(tokens) == 0 {
		// we have a leaf node
		if len(wildcardKeys) != 0 {
			// Ensure the current wildcard keys are the same as the old ones.
			if len(t.wildcardKeys) != 0 && !slices.Equal(t.wildcardKeys, wildcardKeys) {
				return nil, fmt.Errorf("%w: tokens are ambiguous - wildcard keys differ", ErrInvalidPath)
			}

			t.wildcardKeys = wildcardKeys
		}

		return t, nil
	}

	token := tokens[0]
	nextSeparator := strings.IndexByte(tokens, separator)

	switch {
	case token == separator:
		thisToken = string(separator)
		tokenEnd = 1
	case nextSeparator == -1:
		thisToken = tokens
		tokenEnd = len(tokens)
	default:
		thisToken = tokens[0:nextSeparator]
		tokenEnd = nextSeparator
	}

	remainder := tokens[tokenEnd:]

	if !inStaticToken { //nolint:nestif
		switch token {
		case '*':
			thisToken = thisToken[1:]
			if isHostPart && len(thisToken) != 0 {
				return nil, fmt.Errorf("%w: named free wildcards are not supported in host patterns",
					ErrInvalidHost)
			}

			if nextSeparator != -1 {
				if isHostPart {
					return nil, fmt.Errorf("%w: %s has '.' before a free wildcard", ErrInvalidHost, tokens)
				}

				return nil, fmt.Errorf("%w: %s has '/' after a free wildcard", ErrInvalidPath, tokens)
			}

			if t.catchAllChild == nil {
				t.catchAllChild = &Trie[V]{
					token:      thisToken,
					isCatchAll: true,
					isHostNode: isHostPart,
					canAdd:     t.canAdd,
				}

				if len(t.values) == 0 {
					t.canBacktrack = func(_ []V) bool { return true }
				}
			}

			if tokens[1:] != t.catchAllChild.token {
				return nil, fmt.Errorf("%w: free wildcard name in %s doesn't match %s",
					ErrInvalidPath, tokens, t.catchAllChild.token)
			}

			if isHostPart {
				return t.catchAllChild.addNode("", pathPattern, wildcardKeys, false)
			}

			wildcardKeys = append(wildcardKeys, thisToken)
			t.catchAllChild.wildcardKeys = wildcardKeys

			return t.catchAllChild, nil
		case ':':
			if isHostPart {
				return nil, fmt.Errorf("%w: simple wildcards (:) not supported in host part", ErrInvalidHost)
			}

			if t.wildcardChild == nil {
				t.wildcardChild = &Trie[V]{
					token:      "wildcard",
					isWildcard: true,
					isHostNode: isHostPart,
					canAdd:     t.canAdd,
				}

				if len(t.values) == 0 {
					t.canBacktrack = func(_ []V) bool { return true }
				}
			}

			return t.wildcardChild.addNode("", remainder, append(wildcardKeys, thisToken[1:]), false)
		}
	}

	if !isHostPart && !inStaticToken &&
		len(thisToken) >= 2 &&
		thisToken[0] == '\\' &&
		(thisToken[1] == '*' || thisToken[1] == ':' || thisToken[1] == '\\') {
		// The token starts with a character escaped by a backslash. Drop the backslash.
		token = thisToken[1]
		thisToken = thisToken[1:]
		unescaped = true
	}

	for i, index := range t.staticIndices {
		if token == index {
			// Yes. Split it based on the common prefix of the existing
			// node and the new one.
			child, prefixSplit := t.splitCommonPrefix(i, thisToken)
			child.priority++

			t.sortStaticChildren(i)

			if unescaped {
				// Account for the removed backslash.
				prefixSplit++
			}

			// Ensure that the rest of this token is not mistaken for a wildcard
			// if a prefix split occurs at a '*' or ':'.
			if isHostPart {
				return child.addNode(tokens[prefixSplit:], pathPattern, wildcardKeys, token != separator)
			}

			return child.addNode("", tokens[prefixSplit:], wildcardKeys, token != separator)
		}
	}

	child := &Trie[V]{
		token:      thisToken,
		isHostNode: isHostPart,
		canAdd:     t.canAdd,
	}

	t.staticIndices = append(t.staticIndices, token)
	t.staticChildren = append(t.staticChildren, child)

	if len(t.values) == 0 {
		t.canBacktrack = func(_ []V) bool { return true }
	}

	// Ensure that the rest of this token is not mistaken for a wildcard
	// if a prefix split occurs at a '*' or ':'.
	if isHostPart {
		return child.addNode(remainder, pathPattern, wildcardKeys, token != separator)
	}

	return child.addNode("", remainder, wildcardKeys, token != separator)
}

//nolint:cyclop,funlen,gocognit,gocyclo
func (t *Trie[V]) deleteNode(
	hostPattern, pathPattern string,
	matcher ValueMatcher[V],
) bool {
	// Determine which part we're processing and get the appropriate string and separator
	var (
		tokens     string
		separator  byte
		isHostPart bool

		nextTokens string
		child      *Trie[V]
	)

	if len(hostPattern) != 0 {
		tokens = hostPattern
		separator = '.'
		isHostPart = true
	} else {
		tokens = pathPattern
		separator = '/'
		isHostPart = false
	}

	if len(tokens) == 0 {
		if len(t.values) == 0 {
			return false
		}

		oldSize := len(t.values)
		t.values = slices.DeleteFunc(t.values, matcher.Match)
		newSize := len(t.values)

		if newSize == 0 {
			t.canBacktrack = func(_ []V) bool { return true }
		}

		return oldSize != newSize
	}

	token := tokens[0]

	if len(t.token) == 0 || t.token == unsafe.String(&separator, 1) {
		switch token {
		case ':':
			// Only valid for paths
			if isHostPart || t.wildcardChild == nil {
				return false
			}

			child = t.wildcardChild
			nextSeparator := t.nextSeparator(tokens, separator)
			nextTokens = tokens[nextSeparator:]
		case '*':
			if t.catchAllChild == nil {
				return false
			}

			child = t.catchAllChild
			nextTokens = ""
		}
	}

	if child != nil {
		var deleted bool
		if isHostPart {
			deleted = child.deleteNode(nextTokens, pathPattern, matcher)
		} else {
			deleted = child.deleteNode("", nextTokens, matcher)
		}

		if deleted && len(child.values) == 0 {
			t.deleteChild(child, token)
		}

		return deleted
	}

	if !isHostPart &&
		len(tokens) >= 2 &&
		(len(t.token) == 0 || t.token == string(separator)) &&
		tokens[0] == '\\' &&
		(tokens[1] == '*' || tokens[1] == ':' || tokens[1] == '\\') {
		// The token starts with a character escaped by a backslash. Drop the backslash.
		token = tokens[1]
		tokens = tokens[1:]
	}

	for i, staticIndex := range t.staticIndices {
		if token == staticIndex { //nolint: nestif
			child = t.staticChildren[i]
			childTokenLen := len(child.token)

			if len(tokens) >= childTokenLen && child.token == tokens[:childTokenLen] {
				var deleted bool
				if isHostPart {
					deleted = child.deleteNode(tokens[childTokenLen:], pathPattern, matcher)
				} else {
					deleted = child.deleteNode("", tokens[childTokenLen:], matcher)
				}

				if deleted {
					if len(child.values) == 0 {
						t.deleteChild(child, token)
					}

					return true
				}
			}

			break
		}
	}

	return false
}

//nolint:cyclop
func (t *Trie[V]) deleteChild(child *Trie[V], token uint8) {
	separator := byte('/')
	if child.isHostNode {
		separator = '.'
	}

	if len(child.staticIndices) == 1 && child.staticIndices[0] != separator && child.token != string(separator) {
		grandChild := child.staticChildren[0]
		if grandChild.isHostNode != child.isHostNode {
			return
		}

		if len(child.staticChildren) == 1 {
			grandChild.token = child.token + grandChild.token
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
			t.wildcardChild = nil
		case child.isCatchAll:
			t.catchAllChild = nil
		default:
			t.deleteEdge(token)
		}
	}
}

func (t *Trie[V]) deleteEdge(token byte) {
	for i, index := range t.staticIndices {
		if token == index {
			t.staticChildren = append(t.staticChildren[:i], t.staticChildren[i+1:]...)
			t.staticIndices = append(t.staticIndices[:i], t.staticIndices[i+1:]...)

			return
		}
	}
}

//nolint:gocognit,cyclop,gocyclo
func (t *Trie[V]) lookupNodes(hostPattern, pathPattern string, opts *lookupOpts[V]) ([]*Trie[V], error) {
	return opts.ls.lookupNodes(t, hostPattern, pathPattern)
}

//nolint:funlen,gocognit,cyclop
func (t *Trie[V]) findNode(
	host, path string,
	captures []string,
	matcher LookupMatcher[V],
) (*Trie[V], int, []string, CanBacktrackFunc[V]) {
	var (
		tokens     string
		separator  byte
		isHostPart bool

		found *Trie[V]
		idx   int
		value V

		continueLookup bool
	)

	// Determine which part we're processing and get the appropriate string and separator
	if len(host) != 0 {
		tokens = host
		separator = '.'
		isHostPart = true
	} else {
		tokens = path
		separator = '/'
		isHostPart = false
	}

	canBacktrack := t.canBacktrack

	if len(tokens) == 0 {
		for idx, value = range t.values {
			if match := matcher.Match(value, t.wildcardKeys, captures); match {
				return t, idx, captures, nil
			}
		}

		return nil, 0, nil, t.canBacktrack
	}

	// First see if this matches a static token.
	firstChar := tokens[0]
	for i, staticIndex := range t.staticIndices {
		if staticIndex == firstChar { //nolint: nestif
			child := t.staticChildren[i]
			childTokenLen := len(child.token)

			if len(tokens) >= childTokenLen && child.token == tokens[:childTokenLen] {
				nextTokens := tokens[childTokenLen:]
				if isHostPart {
					found, idx, captures, canBacktrack = child.findNode(nextTokens, path, captures, matcher)
				} else {
					found, idx, captures, canBacktrack = child.findNode("", nextTokens, captures, matcher)
				}
			} else {
				continueLookup = true
			}

			break
		}
	}

	if !continueLookup && (found != nil || canBacktrack == nil || !canBacktrack(t.values)) {
		return found, idx, captures, nil
	}

	if !isHostPart && t.wildcardChild != nil { //nolint:nestif
		// Didn't find a static token, so check for a wildcard (only for paths).
		nextSeparator := t.nextSeparator(tokens, separator)
		thisToken := tokens[0:nextSeparator]
		nextToken := tokens[nextSeparator:]

		if len(thisToken) > 0 { // Don't match on empty tokens.
			var tmp []string

			found, idx, tmp, canBacktrack = t.wildcardChild.findNode("", nextToken, append(captures, thisToken), matcher)
			if found != nil {
				return found, idx, tmp, nil
			} else if canBacktrack != nil && !canBacktrack(t.values) {
				return nil, 0, nil, nil
			}
		}
	}

	if t.catchAllChild != nil {
		if isHostPart {
			// Transit to path part
			return t.catchAllChild.findNode("", path, captures, matcher)
		}

		return t.catchAllChild.findNode("", "", append(captures, tokens), matcher)
	}

	return nil, 0, captures, canBacktrack
}

func (t *Trie[V]) splitCommonPrefix(existingNodeIndex int, token string) (*Trie[V], int) {
	childNode := t.staticChildren[existingNodeIndex]

	if strings.HasPrefix(token, childNode.token) {
		// No split needs to be done. Rather, the new path shares the entire
		// prefix with the existing node, so the new node is just a child of
		// the existing one. Or the new path is the same as the existing path,
		// which means that we just move on to the next token. Either way,
		// this return accomplishes that
		return childNode, len(childNode.token)
	}

	// FindEntry the length of the common prefix of the child node and the new path.
	i := commonPrefixLen(childNode.token, token)

	commonPrefix := token[0:i]
	childNode.token = childNode.token[i:]

	// Create a new intermediary node in the place of the existing node, with
	// the existing node as a child.
	newNode := &Trie[V]{
		token:    commonPrefix,
		priority: childNode.priority,
		// Index is the first byte of the non-common part of the path.
		staticIndices:  []byte{childNode.token[0]},
		staticChildren: []*Trie[V]{childNode},
	}
	t.staticChildren[existingNodeIndex] = newNode

	return newNode, i
}

func (t *Trie[V]) FindEntry(host, path string, matcher LookupMatcher[V]) (*Entry[V], error) {
	found, idx, params, _ := t.findNode(reverseHost(host), path, make([]string, 0, 3), matcher)
	if found == nil {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
	}

	entry := &Entry[V]{
		Value:      found.values[idx],
		Parameters: make(map[string]string, len(params)),
	}

	for i, param := range params {
		key := found.wildcardKeys[i]
		if key != "*" {
			entry.Parameters[key] = param
		}
	}

	return entry, nil
}

func (t *Trie[V]) Add(hostPattern, pathPattern string, value V, opts ...AddOption[V]) error {
	node, err := t.addNode(reverseHost(hostPattern), pathPattern, nil, false)
	if err != nil {
		return err
	}

	if !t.canAdd(node.values, value) {
		return fmt.Errorf("%w: %s", ErrConstraintsViolation, pathPattern)
	}

	for _, apply := range opts {
		apply(node)
	}

	node.values = append(node.values, value)

	return nil
}

func (t *Trie[V]) Delete(hostPattern, pathPattern string, matcher ValueMatcher[V]) error {
	if !t.deleteNode(reverseHost(hostPattern), pathPattern, matcher) {
		return fmt.Errorf("%w: %s", ErrFailedToDelete, pathPattern)
	}

	return nil
}

func (t *Trie[V]) Lookup(hostPattern, pathPattern string, opts ...LookupOption[V]) ([]*Trie[V], error) {
	lOpts := &lookupOpts[V]{}

	if len(opts) == 0 {
		opts = append(opts, WithExactMatch[V]())
	}

	for _, opt := range opts {
		opt(lOpts)
	}

	return t.lookupNodes(reverseHost(hostPattern), pathPattern, lOpts)
}

func (t *Trie[V]) Empty() bool {
	return len(t.values) == 0 && len(t.staticChildren) == 0 && t.wildcardChild == nil && t.catchAllChild == nil
}

func (t *Trie[V]) Clone() *Trie[V] {
	root := &Trie[V]{}

	t.cloneInto(root)

	return root
}

func (t *Trie[V]) cloneInto(out *Trie[V]) {
	*out = *t

	if len(t.wildcardKeys) != 0 {
		out.wildcardKeys = slices.Clone(t.wildcardKeys)
	}

	if len(t.values) != 0 {
		out.values = slices.Clone(t.values)
	}

	if t.catchAllChild != nil {
		out.catchAllChild = &Trie[V]{}
		t.catchAllChild.cloneInto(out.catchAllChild)
	}

	if t.wildcardChild != nil {
		out.wildcardChild = &Trie[V]{}
		t.wildcardChild.cloneInto(out.wildcardChild)
	}

	if len(t.staticChildren) != 0 {
		out.staticIndices = slices.Clone(t.staticIndices)
		out.staticChildren = make([]*Trie[V], len(t.staticChildren))

		for idx, child := range t.staticChildren {
			newChild := &Trie[V]{}

			child.cloneInto(newChild)
			out.staticChildren[idx] = newChild
		}
	}
}
