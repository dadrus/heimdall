package radixtree

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func BenchmarkNodeSearchNoPaths(b *testing.B) {
	tm := testMatcher[string](true)
	tree := &node[string]{
		path:   "/",
		canAdd: func(_ []string, _ string) bool { return true },
	}

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		tree.findNode("", tm)
	}
}

func BenchmarkNodeSearchRoot(b *testing.B) {
	tm := testMatcher[string](true)
	tree := &node[string]{
		path:   "/",
		canAdd: func(_ []string, _ string) bool { return true },
	}

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		tree.findNode("/", tm)
	}
}

func BenchmarkNodeSearchOneStaticPath(b *testing.B) {
	tm := testMatcher[string](true)
	tree := &node[string]{
		path:   "/",
		canAdd: func(_ []string, _ string) bool { return true },
	}

	tree.Add("abc", "foo")

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		tree.findNode("abc", tm)
	}
}

func BenchmarkNodeSearchOneLongStaticPath(b *testing.B) {
	tm := testMatcher[string](true)
	tree := &node[string]{
		path:   "/",
		canAdd: func(_ []string, _ string) bool { return true },
	}

	tree.Add("foo/bar/baz", "foo")

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		tree.findNode("foo/bar/baz", tm)
	}
}

func BenchmarkNodeSearchOneWildcardPath(b *testing.B) {
	tm := testMatcher[string](true)
	tree := &node[string]{
		path:   "/",
		canAdd: func(_ []string, _ string) bool { return true },
	}

	require.NoError(b, tree.Add(":abc", "foo"))

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		tree.findNode("abc", tm)
	}
}

func BenchmarkNodeSearchOneLongWildcards(b *testing.B) {
	tm := testMatcher[string](true)
	tree := &node[string]{
		path:   "/",
		canAdd: func(_ []string, _ string) bool { return true },
	}

	tree.Add(":abc/:def/:ghi", "foo")

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		tree.findNode("abcdefghijklmnop/aaaabbbbccccddddeeeeffffgggg/hijkl", tm)
	}
}

func BenchmarkNodeSearchOneFreeWildcard(b *testing.B) {
	tm := testMatcher[string](true)
	tree := &node[string]{
		path:   "/",
		canAdd: func(_ []string, _ string) bool { return true },
	}

	require.NoError(b, tree.Add("*abc", "foo"))

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		tree.findNode("foo", tm)
	}
}
