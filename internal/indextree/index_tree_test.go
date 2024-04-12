package indextree

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestFoo(t *testing.T) {
	t.Parallel()

	tree := NewIndexTree[string]()

	err := tree.Add("*.github.com", "/images/abc.jpg", "1")
	require.NoError(t, err)

	err = tree.Add("*.github.com", "/images/abc.jpg", "2")
	require.NoError(t, err)

	err = tree.Add("*.github.com", "/images/:imgname", "3")
	require.NoError(t, err)

	err = tree.Add("www.github.com", "/images/*path", "4")
	require.NoError(t, err)

	val, params, err := tree.Find("imgs.github.com", "/images/abc.jpg", testMatcher[string](true))
	require.NoError(t, err)
	assert.Equal(t, "1", val)
	assert.Empty(t, params)

	val, params, err = tree.Find("imgs.github.com", "/images/abc.jpg", MatcherFunc[string](func(value string) bool {
		return value == "2"
	}))
	require.NoError(t, err)
	assert.Equal(t, "2", val)
	assert.Empty(t, params)

	val, params, err = tree.Find("imgs.github.com", "/images/cba.jpg", testMatcher[string](true))
	require.NoError(t, err)
	assert.Equal(t, "3", val)
	assert.Equal(t, map[string]string{"imgname": "cba.jpg"}, params)

	_, _, err = tree.Find("imgs.github.com", "/images/cba/abc.jpg", testMatcher[string](true))
	require.Error(t, err)

	val, params, err = tree.Find("www.github.com", "/images/cba.jpg", testMatcher[string](true))
	require.NoError(t, err)
	assert.Equal(t, "4", val)
	assert.Equal(t, map[string]string{"path": "cba.jpg"}, params)

	val, params, err = tree.Find("www.github.com", "/images/abc/cba.jpg", testMatcher[string](true))
	require.NoError(t, err)
	assert.Equal(t, "4", val)
	assert.Equal(t, map[string]string{"path": "abc/cba.jpg"}, params)
}
