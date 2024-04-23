package radixtree

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func BenchmarkNodeSearchNoPaths(b *testing.B) {
	tm := testMatcher[string](true)
	tree := &Tree[string]{
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
	tree := &Tree[string]{
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
	tree := &Tree[string]{
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
	tree := &Tree[string]{
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
	tree := &Tree[string]{
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
	tree := &Tree[string]{
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
	tree := &Tree[string]{
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

func BenchmarkNodeSearchRandomPathInBigTree(b *testing.B) {
	tm := testMatcher[string](true)
	tree := &Tree[string]{
		path:   "/",
		canAdd: func(_ []string, _ string) bool { return true },
	}

	paths := make([]string, 0, 1000)

	for range cap(paths) {
		builder := strings.Builder{}
		builder.WriteString("/")
		builder.WriteString(randStringBytes(5))

		for range 4 {
			builder.WriteString("/")
			builder.WriteString(randStringBytes(5))
		}

		path := builder.String()
		paths = append(paths, path)

		require.NoError(b, tree.Add(path, path))
	}

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		path := paths[rand.Intn(len(paths))]
		tree.findNode(path, tm)
	}
}

func BenchmarkNodeCloneSmallTree(b *testing.B) {
	tree := &Tree[string]{
		path:   "/",
		canAdd: func(_ []string, _ string) bool { return true },
	}

	for _, path := range []string{
		"/abc/abc", "/abb/abc", "/abd/abc", "/bbc/abc",
	} {
		require.NoError(b, tree.Add(path, path))
	}

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		tree.Clone()
	}
}

func BenchmarkNodeCloneBigTree(b *testing.B) {
	tree := &Tree[string]{
		path:   "/",
		canAdd: func(_ []string, _ string) bool { return true },
	}

	for range 1000 {
		builder := strings.Builder{}
		builder.WriteString("/")
		builder.WriteString(randStringBytes(5))

		for range 4 {
			builder.WriteString("/")
			builder.WriteString(randStringBytes(5))
		}

		path := builder.String()

		require.NoError(b, tree.Add(path, path))
	}

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		tree.Clone()
	}
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func randStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}
