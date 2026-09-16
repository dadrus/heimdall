// Copyright 2025 Dimitrij Drus <dadrus@gmx.de>
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

import "unsafe"

type exactLookupStrategy[V any] struct{}

// nolint: gocognit, unused, cyclop
func (s exactLookupStrategy[V]) lookupNodes(trie *Trie[V], hostPattern, pathPattern string) ([]*Trie[V], error) {
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
		return []*Trie[V]{trie}, nil
	}

	token := tokens[0]

	if len(trie.token) == 0 || trie.token == unsafe.String(&separator, 1) {
		switch token {
		case ':':
			// Only valid for paths
			if isHostPart || trie.wildcardChild == nil {
				return nil, ErrNotFound
			}

			child = trie.wildcardChild
			nextSeparator := trie.nextSeparator(tokens, separator)
			nextTokens = tokens[nextSeparator:]
		case '*':
			if trie.catchAllChild == nil {
				return nil, ErrNotFound
			}

			child = trie.catchAllChild
			nextTokens = ""
		}
	}

	if child != nil {
		if isHostPart {
			return s.lookupNodes(child, nextTokens, pathPattern)
		}

		return s.lookupNodes(child, "", nextTokens)
	}

	if !isHostPart &&
		len(tokens) >= 2 &&
		(len(trie.token) == 0 || trie.token == unsafe.String(&separator, 1)) &&
		tokens[0] == '\\' &&
		(tokens[1] == '*' || tokens[1] == ':' || tokens[1] == '\\') {
		// The token starts with a character escaped by a backslash. Drop the backslash.
		token = tokens[1]
		tokens = tokens[1:]
	}

	for i, staticIndex := range trie.staticIndices {
		if token == staticIndex { //nolint: nestif
			child = trie.staticChildren[i]
			childTokenLen := len(child.token)

			if len(tokens) >= childTokenLen && child.token == tokens[:childTokenLen] {
				if isHostPart {
					return s.lookupNodes(child, tokens[childTokenLen:], pathPattern)
				}

				return s.lookupNodes(child, "", tokens[childTokenLen:])
			}

			break
		}
	}

	return nil, ErrNotFound
}
