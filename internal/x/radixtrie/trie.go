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

package radixtree

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

var (
	ErrInvalidPath          = errors.New("invalid path")
	ErrInvalidHost          = errors.New("invalid host")
	ErrNotFound             = errors.New("not found")
	ErrFailedToDelete       = errors.New("failed to delete")
	ErrConstraintsViolation = errors.New("constraints violation")
)

type (
	ConstraintsFunc[V any] func(oldValues []V, newValue V) bool

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
		backtrackingEnabled bool
	}
)

func New[V any](opts ...Option[V]) *Trie[V] {
	root := &Trie[V]{
		canAdd:     func(_ []V, _ V) bool { return true },
		isHostNode: true,
	}

	for _, opt := range opts {
		opt(root)
	}

	return root
}

func (n *Trie[V]) sortStaticChildren(i int) {
	for i > 0 && n.staticChildren[i].priority > n.staticChildren[i-1].priority {
		n.staticChildren[i], n.staticChildren[i-1] = n.staticChildren[i-1], n.staticChildren[i]
		n.staticIndices[i], n.staticIndices[i-1] = n.staticIndices[i-1], n.staticIndices[i]

		i--
	}
}

func (n *Trie[V]) nextSeparator(token string, separator byte) int {
	if idx := strings.IndexByte(token, separator); idx != -1 {
		return idx
	}

	return len(token)
}

//nolint:funlen,gocognit,cyclop,gocyclo
func (n *Trie[V]) addNode(
	host, path string,
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

	if len(host) != 0 {
		tokens = host
		separator = '.'
		isHostPart = true
	} else {
		tokens = path
		separator = '/'
		isHostPart = false
	}

	if len(tokens) == 0 {
		// we have a leaf node
		if len(wildcardKeys) != 0 {
			// Ensure the current wildcard keys are the same as the old ones.
			if len(n.wildcardKeys) != 0 && !slices.Equal(n.wildcardKeys, wildcardKeys) {
				return nil, fmt.Errorf("%w: tokens are ambiguous - wildcard keys differ", ErrInvalidPath)
			}

			n.wildcardKeys = wildcardKeys
		}

		return n, nil
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

			if n.catchAllChild == nil {
				n.catchAllChild = &Trie[V]{
					token:      thisToken,
					isCatchAll: true,
					isHostNode: isHostPart,
					canAdd:     n.canAdd,
				}

				if len(n.values) == 0 {
					n.backtrackingEnabled = true
				}
			}

			if tokens[1:] != n.catchAllChild.token {
				return nil, fmt.Errorf("%w: free wildcard name in %s doesn't match %s",
					ErrInvalidPath, tokens, n.catchAllChild.token)
			}

			if isHostPart {
				return n.catchAllChild.addNode("", path, wildcardKeys, false)
			}

			wildcardKeys = append(wildcardKeys, thisToken)
			n.catchAllChild.wildcardKeys = wildcardKeys

			return n.catchAllChild, nil
		case ':':
			if isHostPart {
				return nil, fmt.Errorf("%w: simple wildcards (:) not supported in host part", ErrInvalidHost)
			}

			if n.wildcardChild == nil {
				n.wildcardChild = &Trie[V]{
					token:      "wildcard",
					isWildcard: true,
					isHostNode: isHostPart,
					canAdd:     n.canAdd,
				}

				if len(n.values) == 0 {
					n.backtrackingEnabled = true
				}
			}

			return n.wildcardChild.addNode("", remainder, append(wildcardKeys, thisToken[1:]), false)
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
			if isHostPart {
				return child.addNode(tokens[prefixSplit:], path, wildcardKeys, token != separator)
			}

			return child.addNode("", tokens[prefixSplit:], wildcardKeys, token != separator)
		}
	}

	child := &Trie[V]{
		token:      thisToken,
		isHostNode: isHostPart,
		canAdd:     n.canAdd,
	}

	n.staticIndices = append(n.staticIndices, token)
	n.staticChildren = append(n.staticChildren, child)

	if len(n.values) == 0 {
		n.backtrackingEnabled = true
	}

	// Ensure that the rest of this token is not mistaken for a wildcard
	// if a prefix split occurs at a '*' or ':'.
	if isHostPart {
		return child.addNode(remainder, path, wildcardKeys, token != separator)
	}

	return child.addNode("", remainder, wildcardKeys, token != separator)
}

//nolint:cyclop,funlen,gocognit
func (n *Trie[V]) deleteNode(
	host, path string,
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

	if len(host) != 0 {
		tokens = host
		separator = '.'
		isHostPart = true
	} else {
		tokens = path
		separator = '/'
		isHostPart = false
	}

	if len(tokens) == 0 {
		if len(n.values) == 0 {
			return false
		}

		oldSize := len(n.values)
		n.values = slices.DeleteFunc(n.values, matcher.Match)
		newSize := len(n.values)

		if newSize == 0 {
			n.backtrackingEnabled = true
		}

		return oldSize != newSize
	}

	token := tokens[0]

	switch token {
	case ':':
		// Only valid for paths
		if isHostPart || n.wildcardChild == nil {
			return false
		}

		child = n.wildcardChild
		nextSeparator := n.nextSeparator(tokens, separator)
		nextTokens = tokens[nextSeparator:]
	case '*':
		if n.catchAllChild == nil {
			return false
		}

		child = n.catchAllChild
		nextTokens = ""
	}

	if child != nil {
		var deleted bool
		if isHostPart {
			deleted = child.deleteNode(nextTokens, path, matcher)
		} else {
			deleted = child.deleteNode("", nextTokens, matcher)
		}

		if deleted && len(child.values) == 0 {
			n.deleteChild(child, token)
		}

		return deleted
	}

	if !isHostPart && len(tokens) >= 2 &&
		tokens[0] == '\\' &&
		(tokens[1] == '*' || tokens[1] == ':' || tokens[1] == '\\') {
		// The token starts with a character escaped by a backslash. Drop the backslash.
		token = tokens[1]
		tokens = tokens[1:]
	}

	for i, staticIndex := range n.staticIndices {
		if token == staticIndex { //nolint: nestif
			child = n.staticChildren[i]
			childTokenLen := len(child.token)

			if len(tokens) >= childTokenLen && child.token == tokens[:childTokenLen] {
				var deleted bool
				if isHostPart {
					deleted = child.deleteNode(tokens[childTokenLen:], path, matcher)
				} else {
					deleted = child.deleteNode("", tokens[childTokenLen:], matcher)
				}

				if deleted {
					if len(child.values) == 0 {
						n.deleteChild(child, token)
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
func (n *Trie[V]) deleteChild(child *Trie[V], token uint8) {
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
			n.wildcardChild = nil
		case child.isCatchAll:
			n.catchAllChild = nil
		default:
			n.deleteEdge(token)
		}
	}
}

func (n *Trie[V]) deleteEdge(token byte) {
	for i, index := range n.staticIndices {
		if token == index {
			n.staticChildren = append(n.staticChildren[:i], n.staticChildren[i+1:]...)
			n.staticIndices = append(n.staticIndices[:i], n.staticIndices[i+1:]...)

			return
		}
	}
}

//nolint:funlen,gocognit,cyclop
func (n *Trie[V]) findNode(
	host, path string,
	captures []string,
	matcher LookupMatcher[V],
) (*Trie[V], int, []string, bool) {
	var (
		tokens     string
		separator  byte
		isHostPart bool

		found *Trie[V]
		idx   int
		value V
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

	backtrack := true

	if len(tokens) == 0 {
		if len(n.values) == 0 {
			return nil, 0, nil, true
		}

		for idx, value = range n.values {
			if match := matcher.Match(value, n.wildcardKeys, captures); match {
				return n, idx, captures, false
			}
		}

		return nil, 0, nil, n.backtrackingEnabled
	}

	// First see if this matches a static token.
	firstChar := tokens[0]
	for i, staticIndex := range n.staticIndices {
		if staticIndex == firstChar {
			child := n.staticChildren[i]
			childTokenLen := len(child.token)

			if len(tokens) >= childTokenLen && child.token == tokens[:childTokenLen] {
				nextTokens := tokens[childTokenLen:]
				if isHostPart {
					found, idx, captures, backtrack = child.findNode(nextTokens, path, captures, matcher)
				} else {
					found, idx, captures, backtrack = child.findNode("", nextTokens, captures, matcher)
				}
			}

			break
		}
	}

	if found != nil || !backtrack {
		return found, idx, captures, backtrack
	}

	if !isHostPart && n.wildcardChild != nil { //nolint:nestif
		// Didn't find a static token, so check for a wildcard (only for paths).
		nextSeparator := n.nextSeparator(tokens, separator)
		thisToken := tokens[0:nextSeparator]
		nextToken := tokens[nextSeparator:]

		if len(thisToken) > 0 { // Don't match on empty tokens.
			var tmp []string

			found, idx, tmp, backtrack = n.wildcardChild.findNode("", nextToken, append(captures, thisToken), matcher)
			if found != nil {
				return found, idx, tmp, backtrack
			} else if !backtrack {
				return nil, 0, nil, false
			}
		}
	}

	if n.catchAllChild != nil {
		if isHostPart {
			// Transit to path part
			return n.catchAllChild.findNode("", path, captures, matcher)
		}

		// Just assign the whole remaining tokens.
		for idx, value = range n.catchAllChild.values {
			if match := matcher.Match(value, n.wildcardKeys, captures); match {
				return n.catchAllChild, idx, append(captures, tokens), false
			}
		}

		return nil, 0, captures, n.backtrackingEnabled
	}

	return nil, 0, captures, true
}

func (n *Trie[V]) splitCommonPrefix(existingNodeIndex int, token string) (*Trie[V], int) {
	childNode := n.staticChildren[existingNodeIndex]

	if strings.HasPrefix(token, childNode.token) {
		// No split needs to be done. Rather, the new path shares the entire
		// prefix with the existing node, so the new node is just a child of
		// the existing one. Or the new path is the same as the existing path,
		// which means that we just move on to the next token. Either way,
		// this return accomplishes that
		return childNode, len(childNode.token)
	}

	// Find the length of the common prefix of the child node and the new path.
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
	n.staticChildren[existingNodeIndex] = newNode

	return newNode, i
}

func (n *Trie[V]) Find(host, path string, matcher LookupMatcher[V]) (*Entry[V], error) {
	found, idx, params, _ := n.findNode(reverseHost(host), path, make([]string, 0, 3), matcher)
	if found == nil {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
	}

	entry := &Entry[V]{
		Value: found.values[idx],
	}

	entry.Parameters = make(map[string]string, len(params))

	for i, param := range params {
		key := found.wildcardKeys[i]
		if key != "*" {
			entry.Parameters[key] = param
		}
	}

	return entry, nil
}

func (n *Trie[V]) Add(host, path string, value V, opts ...AddOption[V]) error {
	node, err := n.addNode(reverseHost(host), path, nil, false)
	if err != nil {
		return err
	}

	if !n.canAdd(node.values, value) {
		return fmt.Errorf("%w: %s", ErrConstraintsViolation, path)
	}

	for _, apply := range opts {
		apply(node)
	}

	node.values = append(node.values, value)

	return nil
}

func (n *Trie[V]) Delete(host, path string, matcher ValueMatcher[V]) error {
	if !n.deleteNode(reverseHost(host), path, matcher) {
		return fmt.Errorf("%w: %s", ErrFailedToDelete, path)
	}

	return nil
}

func (n *Trie[V]) Empty() bool {
	return len(n.values) == 0 && len(n.staticChildren) == 0 && n.wildcardChild == nil && n.catchAllChild == nil
}

func (n *Trie[V]) Clone() *Trie[V] {
	root := &Trie[V]{}

	n.cloneInto(root)

	return root
}

func (n *Trie[V]) cloneInto(out *Trie[V]) {
	*out = *n

	if len(n.wildcardKeys) != 0 {
		out.wildcardKeys = slices.Clone(n.wildcardKeys)
	}

	if len(n.values) != 0 {
		out.values = slices.Clone(n.values)
	}

	if n.catchAllChild != nil {
		out.catchAllChild = &Trie[V]{}
		n.catchAllChild.cloneInto(out.catchAllChild)
	}

	if n.wildcardChild != nil {
		out.wildcardChild = &Trie[V]{}
		n.wildcardChild.cloneInto(out.wildcardChild)
	}

	if len(n.staticChildren) != 0 {
		out.staticIndices = slices.Clone(n.staticIndices)
		out.staticChildren = make([]*Trie[V], len(n.staticChildren))

		for idx, child := range n.staticChildren {
			newChild := &Trie[V]{}

			child.cloneInto(newChild)
			out.staticChildren[idx] = newChild
		}
	}
}
