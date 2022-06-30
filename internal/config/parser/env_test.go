package parser

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExpandSlices(t *testing.T) {
	// WHEN
	result := expandSlices(strings.Split("1_2_3", "_"))

	// THEN
	assert.Equal(t, 4, len(result))
	assert.Equal(t, "1.2.3", result[0])
	assert.Equal(t, "1_2.3", result[1])
	assert.Equal(t, "1.2_3", result[2])
	assert.Equal(t, "1_2_3", result[3])
}

func TestKoanfFromEnv(t *testing.T) {
	// GIVEN
	t.Setenv("SOME_STRING_KEY", "some string value")
	t.Setenv("SOMEBOOL_KEY", "true")
	t.Setenv("SOMEINTKEY", "1876")

	// WHEN
	konf, err := koanfFromEnv()

	// THEN
	require.NoError(t, err)

	assert.Equal(t, "some string value", konf.Get("some.string.key")) // some: string: key: ...
	assert.Equal(t, "some string value", konf.Get("some_string.key")) // some_string: key
	assert.Equal(t, "some string value", konf.Get("some.string_key")) // some: string_key
	assert.Equal(t, "some string value", konf.Get("some_string_key")) // some_string_key: ...
	assert.Equal(t, "true", konf.Get("somebool.key"))                 // somebool: key
	assert.Equal(t, "true", konf.Get("somebool_key"))                 // somebool_key: ...
	assert.Equal(t, "1876", konf.Get("someintkey"))                   // someintkey: ...
}
