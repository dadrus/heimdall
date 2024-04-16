package indextree

import (
	"testing"
)

func BenchmarkNodeSearchNoPaths(b *testing.B) {
	tm := testMatcher[string](true)
	tree := &node[string]{}

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		tree.Find("", tm)
	}
}

func BenchmarkNodeSearchOneStaticPath(b *testing.B) {
	tm := testMatcher[string](true)
	tree := &node[string]{}

	tree.Add("/abc", "foo")

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		tree.Find("/abc", tm)
	}
}

func BenchmarkNodeSearchOneWildcardPath(b *testing.B) {
	tm := testMatcher[string](true)
	tree := &node[string]{}

	tree.Add("/:abc", "foo")

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		tree.Find("/abc", tm)
	}
}

func BenchmarkNodeSearchOneLongWildcards(b *testing.B) {
	tm := testMatcher[string](true)
	tree := &node[string]{}

	tree.Add("/:abc/:def/:ghi", "foo")

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		tree.Find("/abcdefghijklmnop/aaaabbbbccccddddeeeeffffgggg/hijkl", tm)
	}
}
