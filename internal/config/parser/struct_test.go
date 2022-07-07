package parser

import (
	"testing"

	"github.com/knadh/koanf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
)

func TestKoanfFromStruct(t *testing.T) {
	t.Parallel()

	type TestConfigWithUppercase struct {
		ThisIsMissingAKoanfTag string
	}

	type TestNestedConfig struct {
		SomeBool   bool   `koanf:"somebool"`
		SomeString string `koanf:"some_string"`
	}

	type TestConfig struct {
		SomeString string             `koanf:"some_string"`
		SomeInt    int                `koanf:"someint"`
		Nested1    TestNestedConfig   `koanf:"nested1"`
		Nested2    []TestNestedConfig `koanf:"nested_2"`
	}

	for _, tc := range []struct {
		uc     string
		conf   any
		assert func(t *testing.T, err error, konf *koanf.Koanf)
	}{
		{
			uc: "missing koanf tag",
			conf: TestConfigWithUppercase{
				ThisIsMissingAKoanfTag: "don't care",
			},
			assert: func(t *testing.T, err error, konf *koanf.Koanf) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(),
					"field ThisIsMissingAKoanfTag does not have lowercase key, use the `koanf` tag")
			},
		},
		{
			uc: "successful",
			conf: TestConfig{
				SomeString: "foo",
				SomeInt:    42,
				Nested1:    TestNestedConfig{SomeBool: true},
				Nested2:    []TestNestedConfig{{SomeString: "bar"}, {SomeString: "baz"}},
			},
			assert: func(t *testing.T, err error, konf *koanf.Koanf) {
				t.Helper()

				assert.NoError(t, err)
				konf.Print()

				assert.Equal(t, "foo", konf.Get("some_string"))
				assert.Equal(t, 42, konf.Get("someint"))
				assert.Equal(t, true, konf.Get("nested1.somebool"))
				assert.Empty(t, konf.Get("nested1.some_string"))
				assert.Len(t, konf.Get("nested_2"), 2)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			konf, err := koanfFromStruct(tc.conf)

			// THEN
			tc.assert(t, err, konf)
		})
	}
}
