package parser

import (
	"os"
	"testing"

	"github.com/knadh/koanf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKoanfFromYaml(t *testing.T) {
	t.Setenv("FOO", "BAR")

	for _, tc := range []struct {
		uc     string
		config []byte
		assert func(t *testing.T, err error, kanf *koanf.Koanf)
	}{
		{
			uc: "without env substitution",
			config: []byte(`
some_string: foo
someint: 3
nested1:
  somebool: true
  some_string: bar
nested_2:
  - somebool: false
    some_string: baz
`),
			assert: func(t *testing.T, err error, konf *koanf.Koanf) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "foo", konf.Get("some_string"))
				assert.Equal(t, 3, konf.Get("someint"))
				assert.Equal(t, "bar", konf.Get("nested1.some_string"))
				assert.Equal(t, true, konf.Get("nested1.somebool"))
				assert.Len(t, konf.Get("nested_2"), 1)
				assert.Contains(t, konf.Get("nested_2"), map[string]any{"some_string": "baz", "somebool": false})
			},
		},
		{
			uc: "with env substitution",
			config: []byte(`
some_string: ${FOO}
someint: 3
nested1:
  somebool: true
  some_string: bar
nested_2:
  - somebool: false
    some_string: ${BAZ:=zab}
`),
			assert: func(t *testing.T, err error, konf *koanf.Koanf) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "BAR", konf.Get("some_string"))
				assert.Equal(t, 3, konf.Get("someint"))
				assert.Equal(t, "bar", konf.Get("nested1.some_string"))
				assert.Equal(t, true, konf.Get("nested1.somebool"))
				assert.Len(t, konf.Get("nested_2"), 1)
				assert.Contains(t, konf.Get("nested_2"), map[string]any{"some_string": "zab", "somebool": false})
			},
		},
		{
			uc:     "with invalid yaml content",
			config: []byte("foobar"),
			assert: func(t *testing.T, err error, kanf *koanf.Koanf) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, err.Error(), "failed to load")
			},
		},
		{
			uc:     "with invalid env substitution content",
			config: []byte("${:}"),
			assert: func(t *testing.T, err error, kanf *koanf.Koanf) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, err.Error(), "failed to read")
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			tempFile, err := os.CreateTemp("", "config-test-*")
			require.NoError(t, err)

			defer tempFile.Close()

			fileName := tempFile.Name()
			defer os.Remove(fileName)

			_, err = tempFile.Write(tc.config)
			require.NoError(t, err)

			// WHEN
			konf, err := koanfFromYaml(fileName)

			// THEN
			tc.assert(t, err, konf)
		})
	}
}
