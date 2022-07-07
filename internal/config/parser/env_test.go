package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKoanfFromEnv(t *testing.T) {
	// GIVEN
	t.Setenv("FOO_SOME_0_STRING__KEY", "first val")
	t.Setenv("FOO_SOME_0_INT__KEY", "10")
	t.Setenv("FOO_SOME_2_INT__KEY", "11")
	t.Setenv("FOO_SOME_4_DOO_1_FOO__KEY", "bar")
	t.Setenv("FOO_SOME_4_DOO_1_BAR__KEY", "baz")
	t.Setenv("FOO_SOME_4_DOO_0_FOO_KEY", "zab")
	t.Setenv("FOO_FOO_2", "baz")
	t.Setenv("FOO_FOO_1", "bar")
	t.Setenv("FOO_SOME_3_FOO_1", "baz")
	t.Setenv("FOO_SOME_3_FOO_0", "foo")
	t.Setenv("FOO_SOME_3_FOO_0", "zab")
	t.Setenv("FOO_SOME_3_FOO_2", "azb")
	t.Setenv("FOO_A_SIMPLE_KEY", "simple")

	// WHEN
	konf, err := koanfFromEnv("FOO_")

	// THEN
	require.NoError(t, err)

	konf.Print()

	foo := konf.Get("foo")
	slice, ok := foo.([]any)
	require.True(t, ok)
	assert.Len(t, slice, 3)
	assert.Nil(t, slice[0])
	assert.Equal(t, "bar", slice[1])
	assert.Equal(t, "baz", slice[2])

	some := konf.Get("some")
	slice, ok = some.([]any)
	require.True(t, ok)
	assert.Len(t, slice, 5)

	entry1, ok := slice[0].(map[string]any)
	require.True(t, ok)
	assert.Len(t, entry1, 2)
	assert.Equal(t, "10", entry1["int_key"])
	assert.Equal(t, "first val", entry1["string_key"])

	require.Nil(t, slice[1])

	entry3, ok := slice[2].(map[string]any)
	require.True(t, ok)
	assert.Len(t, entry3, 1)
	assert.Equal(t, "11", entry3["int_key"])

	entry4, ok := slice[3].(map[string]any)
	require.True(t, ok)
	assert.Len(t, entry4, 1)
	fooSlice, ok := entry4["foo"].([]any)
	require.True(t, ok)
	assert.Len(t, fooSlice, 3)
	assert.Equal(t, "zab", fooSlice[0])
	assert.Equal(t, "baz", fooSlice[1])
	assert.Equal(t, "azb", fooSlice[2])

	entry5, ok := slice[4].(map[string]any)
	require.True(t, ok)
	assert.Len(t, entry5, 1)
	dooSlice, ok := entry5["doo"].([]any)
	require.True(t, ok)
	assert.Len(t, dooSlice, 2)
	assert.Equal(t, map[string]any{"foo.key": "zab"}, dooSlice[0])
	assert.Equal(t, map[string]any{"bar_key": "baz", "foo_key": "bar"}, dooSlice[1])

	simpleVal := konf.Get("a.simple.key")
	assert.Equal(t, "simple", simpleVal)
}
