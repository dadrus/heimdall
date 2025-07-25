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

func BenchmarkTrieFindEmptyTrie(b *testing.B) {
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

func BenchmarkTrieFindRootPath(b *testing.B) {
	tm := lookupMatcher[string](true)
	tree := &Trie[string]{
		canAdd: func(_ []string, _ string) bool { return true },
	}

	require.NoError(b, tree.Add("*", "/", "*"))
	require.NoError(b, tree.Add("*.com", "/", "*.com"))
	require.NoError(b, tree.Add("example.com", "/", "example.com"))
	require.NoError(b, tree.Add("*.example.com", "/", "*.example.com"))
	require.NoError(b, tree.Add("foo.example.com", "/", "foo.example.com"))
	require.NoError(b, tree.Add("*.foo.example.com", "/", "*.foo.example.com"))
	require.NoError(b, tree.Add("bar.foo.example.com", "/", "bar.foo.example.com"))

	for _, host := range []string{
		"foo.bar",
		"foo.com",
		"example.com",
		"bar.example.com",
		"foo.example.com",
		"baz.foo.example.com",
		"bar.foo.example.com",
	} {
		b.Run(host, func(b *testing.B) {
			host = reverseHost(host)
			b.ReportAllocs()
			b.ResetTimer()

			for range b.N {
				tree.findNode(host, "/", nil, tm)
			}
		})
	}
}

func BenchmarkTrieFindPathForWildcardHost(b *testing.B) {
	tm := lookupMatcher[string](true)
	tree := &Trie[string]{
		canAdd: func(_ []string, _ string) bool { return true },
	}

	require.NoError(b, tree.Add("*", "/*abc", "foo"))
	require.NoError(b, tree.Add("*", "/abc", "foo"))
	require.NoError(b, tree.Add("*", "/:abc", "foo"))
	require.NoError(b, tree.Add("*", "/aaa", "foo"))
	require.NoError(b, tree.Add("*", "/foo/bar/baz", "foo"))
	require.NoError(b, tree.Add("*", "/:abc/:def/:ghi", "foo"))
	require.NoError(b, tree.Add("*", "/aaa/bbb/ccc", "foo"))

	for uc, path := range map[string]string{
		"/baz is matched by /*abc":                   "/baz",
		"/abc is matched by /abc":                    "/abc",
		"/foo is matched by /:abc":                   "/foo",
		"/aaa is matched by /aaa":                    "/aaa",
		"/foo/bar/baz is matched by /foo/bar/baz":    "/foo/bar/baz",
		"/bla/bla/bla is matched by /:abc/:def/:ghi": "/bla/bla/bla",
		"/aaa/bbb/ccc is matched by /aaa/bbb/ccc":    "/aaa/bbb/ccc",
	} {
		b.Run(uc, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()

			for range b.N {
				tree.findNode("*", path, nil, tm)
			}
		})
	}
}
