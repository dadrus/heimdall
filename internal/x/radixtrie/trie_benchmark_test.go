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
	"testing"

	"github.com/stretchr/testify/require"
)

func BenchmarkNodeSearchNoPaths(b *testing.B) {
	tm := lookupMatcher[string](true)
	tree := &Trie[string]{
		canAdd: func(_ []string, _ string) bool { return true },
	}

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		tree.findNode("*", "", nil, tm)
	}
}

func BenchmarkNodeSearchRoot(b *testing.B) {
	tm := lookupMatcher[string](true)
	tree := &Trie[string]{
		canAdd: func(_ []string, _ string) bool { return true },
	}

	require.NoError(b, tree.Add("*", "/", "foo"))

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		tree.findNode("*", "/", nil, tm)
	}
}

func BenchmarkNodeSearchOneStaticPath(b *testing.B) {
	tm := lookupMatcher[string](true)
	tree := &Trie[string]{
		canAdd: func(_ []string, _ string) bool { return true },
	}

	require.NoError(b, tree.Add("*", "/abc", "foo"))

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		tree.findNode("*", "/abc", nil, tm)
	}
}

func BenchmarkNodeSearchOneLongStaticPath(b *testing.B) {
	tm := lookupMatcher[string](true)
	tree := &Trie[string]{
		canAdd: func(_ []string, _ string) bool { return true },
	}

	require.NoError(b, tree.Add("*", "/foo/bar/baz", "foo"))

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		tree.findNode("*", "foo/bar/baz", nil, tm)
	}
}

func BenchmarkNodeSearchOneWildcardPath(b *testing.B) {
	tm := lookupMatcher[string](true)
	tree := &Trie[string]{
		canAdd: func(_ []string, _ string) bool { return true },
	}

	require.NoError(b, tree.Add("*", "/:abc", "foo"))

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		tree.findNode("*", "/abc", nil, tm)
	}
}

func BenchmarkNodeSearchOneLongWildcards(b *testing.B) {
	tm := lookupMatcher[string](true)
	tree := &Trie[string]{
		canAdd: func(_ []string, _ string) bool { return true },
	}

	require.NoError(b, tree.Add("*", ":abc/:def/:ghi", "foo"))

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		tree.findNode("*", "abcdefghijklmnop/aaaabbbbccccddddeeeeffffgggg/hijkl", nil, tm)
	}
}

func BenchmarkNodeSearchOneFreeWildcard(b *testing.B) {
	tm := lookupMatcher[string](true)
	tree := &Trie[string]{
		canAdd: func(_ []string, _ string) bool { return true },
	}

	require.NoError(b, tree.Add("*", "/*abc", "foo"))

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		tree.findNode("*", "/foo", nil, tm)
	}
}
