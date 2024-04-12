package indextree

import (
	"testing"
)

func BenchmarkNodeSearchNoPaths(b *testing.B) {
	tm := testMatcher[string](true)
	tree := &pathNode[string]{path: "/"}

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		tree.find("", tm)
	}
}

func BenchmarkNodeSearchOneStaticPath(b *testing.B) {
	tm := testMatcher[string](true)
	tree := &pathNode[string]{path: "/"}

	tree.add("abc", "foo")

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		tree.find("abc", tm)
	}
}

func BenchmarkNodeSearchOneWildcardPath(b *testing.B) {
	tm := testMatcher[string](true)
	tree := &pathNode[string]{path: "/"}

	tree.add(":abc", "foo")

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		tree.find("abc", tm)
	}
}

func BenchmarkNodeSearchOneLongWildcards(b *testing.B) {
	tm := testMatcher[string](true)
	tree := &pathNode[string]{path: "/"}

	tree.add(":abc/:def/:ghi", "foo")

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		tree.find("abcdefghijklmnop/aaaabbbbccccddddeeeeffffgggg/hijkl", tm)
	}
}
