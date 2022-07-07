package parser

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKoanfFromYaml(t *testing.T) {
	t.Parallel()

	// GIVEN
	tempFile, err := ioutil.TempFile("", "config-test-*")
	require.NoError(t, err)

	defer tempFile.Close()

	fileName := tempFile.Name()
	defer os.Remove(fileName)

	_, err = tempFile.Write([]byte(`
some_string: foo
someint: 3
nested1:
  somebool: true
  some_string: bar
nested_2:
  - somebool: false
    some_string: baz
`))
	require.NoError(t, err)

	// WHEN
	konf, err := koanfFromYaml(fileName)

	// THEN
	require.NoError(t, err)

	konf.Print()

	assert.Equal(t, "foo", konf.Get("some_string"))
	assert.Equal(t, 3, konf.Get("someint"))
	assert.Equal(t, "bar", konf.Get("nested1.some_string"))
	assert.Equal(t, true, konf.Get("nested1.somebool"))
	assert.Len(t, konf.Get("nested_2"), 1)
	assert.Contains(t, konf.Get("nested_2"), map[string]any{"some_string": "baz", "somebool": false})
}
