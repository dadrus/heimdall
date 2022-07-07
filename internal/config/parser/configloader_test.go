package parser

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigLoaderLoad(t *testing.T) {
	type TestNestedConfig struct {
		SomeString string `koanf:"some_string"`
		SomeInt    int    `koanf:"someint"`
		SomeBool   bool   `koanf:"somebool"`
	}

	type TestConfig struct {
		SomeString string             `koanf:"some_string"`
		SomeInt    int                `koanf:"someint"`
		SomeBool   bool               `koanf:"some_bool"`
		Nested1    TestNestedConfig   `koanf:"nested1"`
		Nested2    []TestNestedConfig `koanf:"nested_2"`
	}

	// test config struct with defaults
	config := TestConfig{
		SomeString: "default value",
		SomeInt:    666,
		Nested2: []TestNestedConfig{
			{
				SomeBool: true,
			},
		},
	}

	// override parts of the above config with values from a yaml config file
	tempFile, err := ioutil.TempFile("", "config-test-*")
	require.NoError(t, err)

	defer tempFile.Close()

	fileName := tempFile.Name()
	defer os.Remove(fileName)

	_, err = tempFile.Write([]byte(`
some_string: "overridden by yaml file"
someint: 10
nested1:
  somebool: true
nested_2:
  - some_string: "from yaml"
`))
	require.NoError(t, err)

	// override parts of the above config with values from env variables
	t.Setenv("CONFIGLOADERTEST_SOME__BOOL", "true")
	t.Setenv("CONFIGLOADERTEST_SOMEINT", "42")
	t.Setenv("CONFIGLOADERTEST_NESTED1_SOME__STRING", "from env")
	t.Setenv("CONFIGLOADERTEST_NESTED1_SOMEINT", "111")
	t.Setenv("CONFIGLOADERTEST_NESTED__2_0_SOMEBOOL", "true")
	t.Setenv("CONFIGLOADERTEST_NESTED__2_0_SOMEINT", "222")
	t.Setenv("CONFIGLOADERTEST_NESTED__2_1_SOMEBOOL", "true")
	t.Setenv("CONFIGLOADERTEST_NESTED__2_1_SOME__STRING", "from env as well")
	t.Setenv("CONFIGLOADERTEST_NESTED__2_1_SOMEINT", "333")

	err = New(
		WithConfigFile(fileName),
		WithEnvPrefix("CONFIGLOADERTEST_"),
	).Load(&config)

	assert.NoError(t, err)

	assert.Equal(t, "overridden by yaml file", config.SomeString) // yaml override
	assert.Equal(t, 42, config.SomeInt)                           // env override
	assert.True(t, config.SomeBool)                               // set by env

	assert.Equal(t, "from env", config.Nested1.SomeString) // set by env
	assert.Equal(t, 111, config.Nested1.SomeInt)           // set by env
	assert.True(t, config.Nested1.SomeBool)                // set by yaml

	assert.Equal(t, "from yaml", config.Nested2[0].SomeString) // set by yaml
	assert.Equal(t, 222, config.Nested2[0].SomeInt)            // set by env
	assert.True(t, config.Nested2[0].SomeBool)                 // set by env

	assert.Equal(t, "from env as well", config.Nested2[1].SomeString) // set by yaml
	assert.Equal(t, 333, config.Nested2[1].SomeInt)                   // set by env
	assert.True(t, config.Nested2[1].SomeBool)                        // set by env
}
