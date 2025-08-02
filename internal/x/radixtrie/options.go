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

type Option[V any] func(n *Trie[V])

func WithValuesConstraints[V any](constraints ConstraintsFunc[V]) Option[V] {
	return func(n *Trie[V]) {
		if constraints != nil {
			n.canAdd = constraints
		}
	}
}

type AddOption[V any] func(n *Trie[V])

func WithBacktrackingControl[V any](canBacktrack CanBacktrackFunc[V]) AddOption[V] {
	return func(n *Trie[V]) {
		if canBacktrack != nil {
			n.canBacktrack = canBacktrack
		}
	}
}

type LookupOption[V any] func(opts *lookupOpts[V])

func WithExactMatch[V any]() LookupOption[V] {
	return func(opts *lookupOpts[V]) {
		opts.ls = exactLookupStrategy[V]{}
	}
}

func WithWildcardMatch[V any]() LookupOption[V] {
	return func(opts *lookupOpts[V]) {
		opts.ls = wildcardLookupStrategy[V]{}
	}
}
