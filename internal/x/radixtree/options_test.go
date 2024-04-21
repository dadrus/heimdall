package radixtree

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValuesConstrainedTree(t *testing.T) {
	t.Parallel()

	// GIVEN
	tree1 := New[string](WithValuesConstraints[string](func(oldValues []string, _ string) bool {
		return len(oldValues) == 0
	}))

	tree2 := New[string]()

	err := tree1.Add("/foo", "bar")
	require.NoError(t, err)

	err = tree2.Add("/foo", "bar")
	require.NoError(t, err)

	// WHEN
	err1 := tree1.Add("/foo", "bar")
	err2 := tree2.Add("/foo", "bar")

	// THEN
	require.Error(t, err1)
	require.NoError(t, err2)
}
