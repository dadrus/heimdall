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
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func BenchmarkTrieFindNodeOnEmptyTrie(b *testing.B) {
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

func BenchmarkTrieFindNodeRootPath(b *testing.B) {
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

func BenchmarkTrieFindNodeForPathUsingWildcardHost(b *testing.B) {
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

func BenchmarkTrieFindEntry(b *testing.B) {
	tm := lookupMatcher[string](true)
	tree := &Trie[string]{
		canAdd: func(_ []string, _ string) bool { return true },
	}

	require.NoError(b, tree.Add("*", "/foo/bar", "1"))
	require.NoError(b, tree.Add("*", "/**", "2"))
	require.NoError(b, tree.Add("*.example.com", "/foo/bar", "3"))
	require.NoError(b, tree.Add("*.example.com", "/foo/:bar", "4"))
	require.NoError(b, tree.Add("*.example.com", "/foo/**", "5"))
	require.NoError(b, tree.Add("foo.example.com", "/foo/bar", "6"))
	require.NoError(b, tree.Add("foo.example.com", "/**", "7"))
	require.NoError(b, tree.Add("baz.example.com", "/**", "8"))

	for uc, tc := range map[string]struct {
		expVal string
		uri    url.URL
	}{
		"foo.bar/foo/bar is matched by 1":             {"1", url.URL{Host: "foo.bar", Path: "/foo/bar"}},
		"foo.bar/foo is matched by 2":                 {"2", url.URL{Host: "foo.bar", Path: "/foo"}},
		"bar.example.com/foo/bar is matched by 3":     {"3", url.URL{Host: "bar.example.com", Path: "/foo/bar"}},
		"bar.example.com/foo/baz is matched by 4":     {"4", url.URL{Host: "bar.example.com", Path: "/foo/baz"}},
		"bar.example.com/foo/baz/foo is matched by 5": {"5", url.URL{Host: "bar.example.com", Path: "/foo/baz/foo"}},
		"foo.example.com/foo/bar is matched by 6":     {"6", url.URL{Host: "foo.example.com", Path: "/foo/bar"}},
		"foo.example.com/bar is matched 7":            {"7", url.URL{Host: "foo.example.com", Path: "/bar"}},
		"foo.example.com/foo/bar is matched by 8":     {"8", url.URL{Host: "baz.example.com", Path: "/foo/bar"}},
		"bla.example.com/bar/foo is matched by 2":     {"2", url.URL{Host: "bla.example.com", Path: "/bar/foo"}},
	} {
		b.Run(uc, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()

			for range b.N {
				entry, err := tree.FindEntry(tc.uri.Host, tc.uri.Path, tm)

				b.StopTimer()
				require.NoError(b, err)
				require.Equal(b, tc.expVal, entry.Value)
				b.StartTimer()
			}
		})
	}
}
