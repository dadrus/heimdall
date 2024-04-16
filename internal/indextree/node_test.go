package indextree

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testMatcher[V any](matches bool) MatcherFunc[V] { return func(_ V) bool { return matches } }

func TestNodeSearch(t *testing.T) {
	t.Parallel()

	// Setup & populate tree
	tree := &node[string]{}

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
		err := tree.Add(path, path)
		require.NoError(t, err)
	}

	trueMatcher := testMatcher[string](true)
	falseMatcher := testMatcher[string](false)

	for _, tc := range []struct {
		path      string
		expPath   string
		expErr    error
		expParams map[string]string
		matcher   Matcher[string]
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
		{path: "/date/2014/ab%2f", expPath: "/date/:year/:month", expParams: map[string]string{"year": "2014", "month": "ab/"}},
		{path: "/post/ab%2fdef/page/2%2f", expPath: "/post/:post/page/:page", expParams: map[string]string{"post": "ab/def", "page": "2/"}},
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
			var matcher Matcher[string]
			if tc.matcher == nil {
				matcher = trueMatcher
			} else {
				matcher = tc.matcher
			}

			resValue, paramList, err := tree.Find(tc.path, matcher)
			if tc.expErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.expErr)

				return
			}

			require.NoError(t, err)
			assert.Equalf(t, tc.expPath, resValue, "Path %s matched %s, expected %s", tc.path, resValue, tc.expPath)
			assert.Equal(t, tc.expParams, paramList, "Path %s expected parameters are %v, saw %v", tc.path, tc.expParams, paramList)
		})
	}
}

func TestNodeAddPathDuplicates(t *testing.T) {
	t.Parallel()

	tree := &node[string]{}
	path := "/date/:year/:month/abc"

	err := tree.Add(path, "first")
	require.NoError(t, err)

	err = tree.Add(path, "second")
	require.NoError(t, err)

	value, params, err := tree.Find("/date/2024/04/abc", MatcherFunc[string](func(value string) bool {
		return value == "first"
	}))
	require.NoError(t, err)
	assert.Equal(t, "first", value)
	assert.Equal(t, map[string]string{"year": "2024", "month": "04"}, params)

	value, params, err = tree.Find("/date/2024/04/abc", MatcherFunc[string](func(value string) bool {
		return value == "second"
	}))
	require.NoError(t, err)
	assert.Equal(t, "second", value)
	assert.Equal(t, map[string]string{"year": "2024", "month": "04"}, params)
}

func TestNodeAddPath(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc         string
		paths      []string
		shouldFail bool
	}{
		{"slash after catch-all", []string{"/abc/*path/"}, true},
		{"path segment after catch-all", []string{"/abc/*path/def"}, true},
		{"conflicting catch-alls", []string{"/abc/*path", "/abc/*paths"}, true},
		{"ambiguous wildcards", []string{"/abc/:foo/:bar", "/abc/:oof/:rab"}, true},
		{"multiple path segments without wildcard", []string{"/", "/i", "/images", "/images/abc.jpg"}, false},
		{"multiple path segments with wildcard", []string{"/i", "/i/:aaa", "/images/:imgname", "/:images/*path", "/ima", "/ima/:par", "/images1"}, false},
		{"multiple wildcards", []string{"/date/:year/:month", "/date/:year/month", "/date/:year/:month/:post"}, false},
		{"escaped : at the beginning of path segment", []string{"/abc/\\:cd"}, false},
		{"escaped * at the beginning of path segment", []string{"/abc/\\*cd"}, false},
		{": in middle of path segment", []string{"/abc/ab:cd"}, false},
		{": in middle of path segment with existing path", []string{"/abc/ab", "/abc/ab:cd"}, false},
		{"* in middle of path segment", []string{"/abc/ab*cd"}, false},
		{"* in middle of path segment with existing path", []string{"/abc/ab", "/abc/ab*cd"}, false},
		{"katakana /マ", []string{"/マ"}, false},
		{"katakana /カ", []string{"/カ"}, false},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			tree := &node[string]{}

			var err error

			for _, path := range tc.paths {
				err = tree.Add(path, path)
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

func TestNodeDeleteStaticPaths(t *testing.T) {
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

	tree := &node[int]{}

	for idx, path := range paths {
		err := tree.Add(path, idx)
		require.NoError(t, err)
	}

	for i := len(paths) - 1; i >= 0; i-- {
		require.True(t, tree.Delete(paths[i], testMatcher[int](true)))
		require.False(t, tree.Delete(paths[i], testMatcher[int](true)))
	}
}

func TestNodeDeleteStaticAndWildcardPaths(t *testing.T) {
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

	tree := &node[int]{}

	for idx, path := range paths {
		err := tree.Add(path, idx+1)
		require.NoError(t, err)
	}

	var deletedPaths []string

	for i := len(paths) - 1; i >= 0; i-- {
		tbdPath := paths[i]
		require.Truef(t, tree.Delete(tbdPath, testMatcher[int](true)), "Should be able to delete %s", paths[i])
		require.Falsef(t, tree.Delete(tbdPath, testMatcher[int](true)), "Should not be able to delete %s", paths[i])

		deletedPaths = append(deletedPaths, tbdPath)

		for idx, path := range paths {
			val, _, err := tree.Find(path, testMatcher[int](true))

			if slices.Contains(deletedPaths, path) {
				require.Errorf(t, err, "Should not be able to find %s after deleting %s", path, tbdPath)
			} else {
				require.NoErrorf(t, err, "Should be able to find %s after deleting %s", path, tbdPath)
				assert.Equal(t, idx+1, val)
			}
		}
	}
}

func TestNodeDeleteMixedPaths(t *testing.T) {
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

	tree := &node[int]{}

	for idx, path := range paths {
		err := tree.Add(path, idx+1)
		require.NoError(t, err)
	}

	for i := len(paths) - 1; i >= 0; i-- {
		require.Truef(t, tree.Delete(paths[i], testMatcher[int](true)), "Should be able to delete %s", paths[i])
		require.Falsef(t, tree.Delete(paths[i], testMatcher[int](true)), "Should not be able to delete %s", paths[i])
	}

	require.True(t, tree.Empty())
}
