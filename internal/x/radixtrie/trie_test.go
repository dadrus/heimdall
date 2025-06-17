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
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func lookupMatcher[V any](matches bool) LookupMatcherFunc[V] {
	return func(_ V, _, _ []string) bool { return matches }
}

func deleteMatcher[V any](matches bool) ValueMatcherFunc[V] {
	return func(_ V) bool { return matches }
}

func TestTrieFindPathWithWildcardHost(t *testing.T) {
	t.Parallel()

	// Setup & populate tree
	tree := New[string]()

	for _, path := range []string{
		"/",
		"/i",
		"/i/:aaa",
		"/images",
		"/images/abc.jpg",
		"/images/:imgname",
		"/images/*path",
		"/ima",
		"/ima/:par",
		"/images1",
		"/images2",
		"/apples",
		"/app/les",
		"/apples1",
		"/appeasement",
		"/appealing",
		"/date/:year/:month",
		"/date/:year/month",
		"/date/:year/:month/abc",
		"/date/:year/:month/:post",
		"/date/:year/:month/*post",
		"/:page",
		"/:page/:index",
		"/post/:post/page/:page",
		"/plaster",
		"/users/:pk/:related",
		"/users/:id/updatePassword",
		"/:something/abc",
		"/:something/def",
		"/something/**",
		"/images/\\*path",
		"/images/\\*patch",
		"/date/\\:year/\\:month",
		"/apples/ab:cde/:fg/*hi",
		"/apples/ab*cde/:fg/*hi",
		"/apples/ab\\*cde/:fg/*hi",
		"/apples/ab*dde",
		"/マ",
		"/カ",
	} {
		err := tree.Add("*", path, path)
		require.NoError(t, err)
	}

	trueMatcher := lookupMatcher[string](true)
	falseMatcher := lookupMatcher[string](false)

	for _, tc := range []struct {
		path      string
		expPath   string
		expErr    error
		expParams map[string]string
		matcher   LookupMatcher[string]
	}{
		{path: "/users/abc/updatePassword", expPath: "/users/:id/updatePassword", expParams: map[string]string{"id": "abc"}},
		{path: "/users/all/something", expPath: "/users/:pk/:related", expParams: map[string]string{"pk": "all", "related": "something"}},
		{path: "/aaa/abc", expPath: "/:something/abc", expParams: map[string]string{"something": "aaa"}},
		{path: "/aaa/def", expPath: "/:something/def", expParams: map[string]string{"something": "aaa"}},
		{path: "/paper", expPath: "/:page", expParams: map[string]string{"page": "paper"}},
		{path: "/", expPath: "/"},
		{path: "/i", expPath: "/i"},
		{path: "/images", expPath: "/images"},
		{path: "/images/abc.jpg", expPath: "/images/abc.jpg"},
		{path: "/images/something", expPath: "/images/:imgname", expParams: map[string]string{"imgname": "something"}},
		{path: "/images/long/path", expPath: "/images/*path", expParams: map[string]string{"path": "long/path"}},
		{path: "/images/long/path", matcher: falseMatcher, expErr: ErrNotFound},
		{path: "/images/even/longer/path", expPath: "/images/*path", expParams: map[string]string{"path": "even/longer/path"}},
		{path: "/ima", expPath: "/ima"},
		{path: "/apples", expPath: "/apples"},
		{path: "/app/les", expPath: "/app/les"},
		{path: "/abc", expPath: "/:page", expParams: map[string]string{"page": "abc"}},
		{path: "/abc/100", expPath: "/:page/:index", expParams: map[string]string{"page": "abc", "index": "100"}},
		{path: "/post/a/page/2", expPath: "/post/:post/page/:page", expParams: map[string]string{"post": "a", "page": "2"}},
		{path: "/date/2014/5", expPath: "/date/:year/:month", expParams: map[string]string{"year": "2014", "month": "5"}},
		{path: "/date/2014/month", expPath: "/date/:year/month", expParams: map[string]string{"year": "2014"}},
		{path: "/date/2014/5/abc", expPath: "/date/:year/:month/abc", expParams: map[string]string{"year": "2014", "month": "5"}},
		{path: "/date/2014/5/def", expPath: "/date/:year/:month/:post", expParams: map[string]string{"year": "2014", "month": "5", "post": "def"}},
		{path: "/date/2014/5/def/hij", expPath: "/date/:year/:month/*post", expParams: map[string]string{"year": "2014", "month": "5", "post": "def/hij"}},
		{path: "/date/2014/5/def/hij/", expPath: "/date/:year/:month/*post", expParams: map[string]string{"year": "2014", "month": "5", "post": "def/hij/"}},
		{path: "/date/2014/ab%2f", expPath: "/date/:year/:month", expParams: map[string]string{"year": "2014", "month": "ab%2f"}},
		{path: "/post/ab%2fdef/page/2%2f", expPath: "/post/:post/page/:page", expParams: map[string]string{"post": "ab%2fdef", "page": "2%2f"}},
		{path: "/ima/bcd/fgh", expErr: ErrNotFound},
		{path: "/date/2014//month", expErr: ErrNotFound},
		{path: "/date/2014/05/", expErr: ErrNotFound}, // Empty catchall should not match
		{path: "/post//abc/page/2", expErr: ErrNotFound},
		{path: "/post/abc//page/2", expErr: ErrNotFound},
		{path: "/post/abc/page//2", expErr: ErrNotFound},
		{path: "//post/abc/page/2", expErr: ErrNotFound},
		{path: "//post//abc//page//2", expErr: ErrNotFound},
		{path: "/something/foo/bar", expPath: "/something/**", expParams: map[string]string{}},
		{path: "/images/*path", expPath: "/images/\\*path"},
		{path: "/images/*patch", expPath: "/images/\\*patch"},
		{path: "/date/:year/:month", expPath: "/date/\\:year/\\:month"},
		{path: "/apples/ab*cde/lala/baba/dada", expPath: "/apples/ab*cde/:fg/*hi", expParams: map[string]string{"fg": "lala", "hi": "baba/dada"}},
		{path: "/apples/ab\\*cde/lala/baba/dada", expPath: "/apples/ab\\*cde/:fg/*hi", expParams: map[string]string{"fg": "lala", "hi": "baba/dada"}},
		{path: "/apples/ab:cde/:fg/*hi", expPath: "/apples/ab:cde/:fg/*hi", expParams: map[string]string{"fg": ":fg", "hi": "*hi"}},
		{path: "/apples/ab*cde/:fg/*hi", expPath: "/apples/ab*cde/:fg/*hi", expParams: map[string]string{"fg": ":fg", "hi": "*hi"}},
		{path: "/apples/ab*cde/one/two/three", expPath: "/apples/ab*cde/:fg/*hi", expParams: map[string]string{"fg": "one", "hi": "two/three"}},
		{path: "/apples/ab*dde", expPath: "/apples/ab*dde"},
		{path: "/マ", expPath: "/マ"},
		{path: "/カ", expPath: "/カ"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			var matcher LookupMatcher[string]
			if tc.matcher == nil {
				matcher = trueMatcher
			} else {
				matcher = tc.matcher
			}

			entry, err := tree.Find("*", tc.path, matcher)
			if tc.expErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.expErr)

				return
			}

			require.NoError(t, err)
			assert.Equalf(t, tc.expPath, entry.Value, "Path %s matched %s, expected %s", tc.path, entry.Value, tc.expPath)

			expParams := tc.expParams
			if expParams == nil {
				expParams = map[string]string{}
			}

			assert.Equal(t, expParams, entry.Parameters, "Path %s expected parameters are %v, saw %v", tc.path, tc.expParams, entry.Parameters)
		})
	}
}

func TestTrieFind(t *testing.T) {
	t.Parallel()

	tree := New[string]()

	require.NoError(t, tree.Add("*", "/foo/bar", "1"))
	require.NoError(t, tree.Add("*", "/**", "2"))
	require.NoError(t, tree.Add("*.example.com", "/foo/bar", "3"))
	require.NoError(t, tree.Add("*.example.com", "/foo/:bar", "4"))
	require.NoError(t, tree.Add("*.example.com", "/foo/*", "5"))
	require.NoError(t, tree.Add("foo.example.com", "/foo/bar", "6"))
	require.NoError(t, tree.Add("foo.example.com", "/**", "7"))
	require.NoError(t, tree.Add("baz.example.com", "/**", "8"))

	entry, err := tree.Find("foo.bar", "/foo/bar", lookupMatcher[string](true))
	require.NoError(t, err)
	assert.Equal(t, "1", entry.Value)

	entry, err = tree.Find("foo.bar", "/foo", lookupMatcher[string](true))
	require.NoError(t, err)
	assert.Equal(t, "2", entry.Value)

	entry, err = tree.Find("bar.example.com", "/foo/bar", lookupMatcher[string](true))
	require.NoError(t, err)
	assert.Equal(t, "3", entry.Value)

	entry, err = tree.Find("bar.example.com", "/foo/baz", lookupMatcher[string](true))
	require.NoError(t, err)
	assert.Equal(t, "4", entry.Value)

	entry, err = tree.Find("bar.example.com", "/foo/baz/foo", lookupMatcher[string](true))
	require.NoError(t, err)
	assert.Equal(t, "5", entry.Value)

	entry, err = tree.Find("foo.example.com", "/foo/bar", lookupMatcher[string](true))
	require.NoError(t, err)
	assert.Equal(t, "6", entry.Value)

	entry, err = tree.Find("foo.example.com", "/bar", lookupMatcher[string](true))
	require.NoError(t, err)
	assert.Equal(t, "7", entry.Value)

	entry, err = tree.Find("baz.example.com", "/foo/bar", lookupMatcher[string](true))
	require.NoError(t, err)
	assert.Equal(t, "8", entry.Value)
}

func TestTrieFindWithBacktrackingEnabled(t *testing.T) {
	t.Parallel()

	// GIVEN
	tree := New[string]()

	err := tree.Add("*.example.com", "/date/:year/abc", "first", WithBacktracking[string](true))
	require.NoError(t, err)

	err = tree.Add("*", "/date/**", "second")
	require.NoError(t, err)

	// WHEN
	entry, err := tree.Find("foo.bar.example.com", "/date/2024/abc",
		LookupMatcherFunc[string](func(value string, _, _ []string) bool { return value != "first" }))

	// THEN
	require.NoError(t, err)
	assert.Equal(t, "second", entry.Value)
}

func TestTrieFindWithBacktrackingDisabled(t *testing.T) {
	t.Parallel()

	// GIVEN
	tree := New[string]()

	err := tree.Add("*.example.com", "/date/:year/abc", "first")
	require.NoError(t, err)

	err = tree.Add("*", "/date/**", "second")
	require.NoError(t, err)

	// WHEN
	entry, err := tree.Find("foo.example.com", "/date/2024/abc",
		LookupMatcherFunc[string](func(value string, _, _ []string) bool {
			return value != "first"
		}))

	// THEN
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNotFound)
	require.Nil(t, entry)
}

func TestTrieAddHostPatternWithNamedFreeWildcard(t *testing.T) {
	t.Parallel()

	tree := New[string]()

	err := tree.Add("*foo.example.com", "/foo/bar", "1")

	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidHost)
	require.ErrorContains(t, err, "named free wildcards")
}

func TestTrieAddHostPatternWithSimpleWildcard(t *testing.T) {
	t.Parallel()

	tree := New[string]()

	err := tree.Add(":.example.com", "/foo/bar", "1")

	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidHost)
	require.ErrorContains(t, err, "simple wildcards (:) not supported")
}

func TestTrieAddDuplicates(t *testing.T) {
	t.Parallel()

	tree := New[string]()
	path := "/date/:year/:month/abc"

	err := tree.Add("*", path, "first")
	require.NoError(t, err)

	err = tree.Add("*", path, "second")
	require.NoError(t, err)

	entry, err := tree.Find("*", "/date/2024/04/abc",
		LookupMatcherFunc[string](func(value string, _, _ []string) bool {
			return value == "first"
		}))
	require.NoError(t, err)
	assert.Equal(t, "first", entry.Value)
	assert.Equal(t, map[string]string{"year": "2024", "month": "04"}, entry.Parameters)

	entry, err = tree.Find("*", "/date/2024/04/abc",
		LookupMatcherFunc[string](func(value string, _, _ []string) bool {
			return value == "second"
		}))
	require.NoError(t, err)
	assert.Equal(t, "second", entry.Value)
	assert.Equal(t, map[string]string{"year": "2024", "month": "04"}, entry.Parameters)
}

func TestTrieAddWithConstraintsVialation(t *testing.T) {
	t.Parallel()

	tree := New[string](WithValuesConstraints[string](
		func(oldValues []string, newValue string) bool {
			return len(oldValues) == 0
		},
	))

	err := tree.Add("*", "/foo/bar", "1")
	require.NoError(t, err)

	err = tree.Add("*", "/foo/bar", "2")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrConstraintsViolation)
	require.ErrorContains(t, err, "/foo/bar")
}

func TestTrieAddWildcardPathsForDifferentHosts(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		hosts      []string
		shouldFail bool
	}{
		"single wildcard host":                                 {[]string{"*"}, false},
		"multiple same wildcard hosts":                         {[]string{"*.example.com", "*.example.com"}, false},
		"multiple same hosts":                                  {[]string{"example.com", "example.com"}, false},
		"multiple different hosts":                             {[]string{"foo.bar.example.com", "bar.foo.example.com"}, false},
		"host with a wildcard in the middle of the definition": {[]string{"foo.*.bar.example.com"}, true},
		"using closed wildcard in host definition":             {[]string{":.example.com", "foo.:.example.com"}, true},
		"mix of different hosts":                               {[]string{"bar.example.com", "bar.foo.com", "foo.bar", "example.com"}, false},
		"katakana マ.カ":                                       {[]string{"マ.カ"}, false},
	} {
		t.Run(uc, func(t *testing.T) {
			tree := New[string]()

			var err error

			for _, host := range tc.hosts {
				err = tree.Add(host, "/", host)
				if err != nil {
					break
				}
			}

			if tc.shouldFail {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestTrieAddPathForWildcardHost(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		paths      []string
		shouldFail bool
	}{
		"slash after catch-all":                          {[]string{"/abc/*path/"}, true},
		"path segment after catch-all":                   {[]string{"/abc/*path/def"}, true},
		"conflicting catch-alls":                         {[]string{"/abc/*path", "/abc/*paths"}, true},
		"ambiguous wildcards":                            {[]string{"/abc/:foo/:bar", "/abc/:oof/:rab"}, true},
		"multiple path segments without wildcard":        {[]string{"/", "/i", "/images", "/images/abc.jpg"}, false},
		"multiple path segments with wildcard":           {[]string{"/i", "/i/:aaa", "/images/:imgname", "/:images/*path", "/ima", "/ima/:par", "/images1"}, false},
		"multiple wildcards":                             {[]string{"/date/:year/:month", "/date/:year/month", "/date/:year/:month/:post"}, false},
		"escaped : at the beginning of path segment":     {[]string{"/abc/\\:cd"}, false},
		"escaped * at the beginning of path segment":     {[]string{"/abc/\\*cd"}, false},
		": in middle of path segment":                    {[]string{"/abc/ab:cd"}, false},
		": in middle of path segment with existing path": {[]string{"/abc/ab", "/abc/ab:cd"}, false},
		"* in middle of path segment":                    {[]string{"/abc/ab*cd"}, false},
		"* in middle of path segment with existing path": {[]string{"/abc/ab", "/abc/ab*cd"}, false},
		"katakana /マ":                                   {[]string{"/マ"}, false},
		"katakana /カ":                                   {[]string{"/カ"}, false},
	} {
		t.Run(uc, func(t *testing.T) {
			tree := New[string]()

			var err error

			for _, path := range tc.paths {
				err = tree.Add("*", path, path)
				if err != nil {
					break
				}
			}

			if tc.shouldFail {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestTrieDeleteStaticPaths(t *testing.T) {
	t.Parallel()

	paths := []string{
		"/apples",
		"/app/les",
		"/abc",
		"/abc/100",
		"/aaa/abc",
		"/aaa/def",
		"/args",
		"/app/les/and/bananas",
		"/app/les/or/bananas",
	}

	tree := New[int]()

	for idx, path := range paths {
		err := tree.Add("*.example.com", path, idx)
		require.NoError(t, err)
	}

	for i := len(paths) - 1; i >= 0; i-- {
		err := tree.Delete("*.example.com", paths[i], deleteMatcher[int](true))
		require.NoError(t, err)

		err = tree.Delete("*.example.com", paths[i], deleteMatcher[int](true))
		require.Error(t, err)
	}
}

func TestTrieDeleteStaticAndWildcardPaths(t *testing.T) {
	t.Parallel()

	paths := []string{
		"/:foo/bar",
		"/:foo/:bar/baz",
		"/apples",
		"/app/awesome/:id",
		"/app/:name/:id",
		"/app/awesome",
		"/abc",
		"/abc/:les",
		"/abc/:les/bananas",
	}

	tree := New[int]()

	for idx, path := range paths {
		err := tree.Add("*.example.com", path, idx+1)
		require.NoError(t, err)
	}

	var deletedPaths []string

	for i := len(paths) - 1; i >= 0; i-- {
		tbdPath := paths[i]

		err := tree.Delete("*.example.com", tbdPath, deleteMatcher[int](true))
		require.NoErrorf(t, err, "Should be able to delete %s", paths[i])

		err = tree.Delete("*.example.com", tbdPath, deleteMatcher[int](true))
		require.Errorf(t, err, "Should not be able to delete %s", paths[i])

		deletedPaths = append(deletedPaths, tbdPath)

		for idx, path := range paths {
			entry, err := tree.Find("*.example.com", path, lookupMatcher[int](true))

			if slices.Contains(deletedPaths, path) {
				require.Errorf(t, err, "Should not be able to find %s after deleting %s", path, tbdPath)
			} else {
				require.NoErrorf(t, err, "Should be able to find %s after deleting %s", path, tbdPath)
				assert.Equal(t, idx+1, entry.Value)
			}
		}
	}
}

func TestTrieDeleteMixedPaths(t *testing.T) {
	t.Parallel()

	paths := []string{
		"/foo/*bar",
		"/:foo/:bar/baz",
		"/apples",
		"/app/awesome/:id",
		"/app/:name/:id",
		"/app/*awesome",
		"/abc/cba",
		"/abc/:les",
		"/abc/les/bananas",
		"/abc/\\:les/bananas",
		"/abc/:les/bananas",
		"/abc/:les/\\*all",
		"/abc/:les/*all",
		"/abb/\\:ba/*all",
		"/abb/:ba/*all",
		"/abb/\\*all",
		"/abb/*all",
	}

	tree := New[int]()

	for idx, path := range paths {
		err := tree.Add("*.example.com", path, idx+1)
		require.NoError(t, err)
	}

	for i := len(paths) - 1; i >= 0; i-- {
		tbdPath := paths[i]

		err := tree.Delete("*.example.com", tbdPath, deleteMatcher[int](true))
		require.NoErrorf(t, err, "Should be able to delete %s", paths[i])

		err = tree.Delete("*.example.com", tbdPath, deleteMatcher[int](true))
		require.Errorf(t, err, "Should not be able to delete %s", paths[i])
	}

	require.True(t, tree.Empty())
}

func TestTrieClone(t *testing.T) {
	t.Parallel()

	tree := New[string]()
	config := map[string][]string{
		"/abc/bca/bbb":   {"example.com", "/abc/bca/bbb"},
		"/abb/abc/bbb":   {"example.com", "/abb/abc/bbb"},
		"/**":            {"*", "/foo"},
		"/abc/*foo":      {"example.com", "/abc/bar/baz"},
		"/:foo/abc":      {"foo.example.com", "/bar/abc"},
		"/:foo/:bar/**":  {"*.example.com", "/bar/baz/foo"},
		"/:foo/:bar/abc": {"*.example.com", "/bar/baz/abc"},
	}

	for expr, value := range config {
		require.NoError(t, tree.Add(value[0], expr, value[1]))
	}

	clone := tree.Clone()

	for _, values := range slices.Collect(maps.Values(config)) {
		entry, err := clone.Find(values[0], values[1],
			LookupMatcherFunc[string](func(_ string, _, _ []string) bool { return true }))

		require.NoError(t, err)
		assert.Equal(t, values[1], entry.Value)
	}
}
