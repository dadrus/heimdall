// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigLoaderLoad(t *testing.T) {
	type NestedValue struct {
		Value string `koanf:"value"`
	}

	type TestNestedConfig struct {
		SomeString string      `koanf:"some_string"`
		SomeInt    int         `koanf:"someint"`
		SomeBool   bool        `koanf:"somebool"`
		Nested     NestedValue `koanf:"inner"`
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
				Nested:   NestedValue{Value: "bar"},
			},
		},
	}

	// override parts of the above config with values from a yaml config file
	tempFile, err := os.CreateTemp(t.TempDir(), "config-test-*")
	require.NoError(t, err)

	defer tempFile.Close()

	fileName := tempFile.Name()

	_, err = tempFile.WriteString(`
some_string: "overridden by yaml file"
someint: 10
nested1:
  somebool: true
nested_2:
  - some_string: "from yaml"
`)
	require.NoError(t, err)

	// override parts of the above config with values from env variables
	t.Setenv("CONFIGLOADERTEST_SOME__BOOL", "true")
	t.Setenv("CONFIGLOADERTEST_SOMEINT", "42")
	t.Setenv("CONFIGLOADERTEST_NESTED1_SOME__STRING", "from env")
	t.Setenv("CONFIGLOADERTEST_NESTED1_SOMEINT", "111")
	t.Setenv("CONFIGLOADERTEST_NESTED1_INNER_VALUE", "bar")
	t.Setenv("CONFIGLOADERTEST_NESTED__2_0_SOMEBOOL", "true")
	t.Setenv("CONFIGLOADERTEST_NESTED__2_0_SOMEINT", "222")
	t.Setenv("CONFIGLOADERTEST_NESTED__2_0_INNER_VALUE", "foo")
	t.Setenv("CONFIGLOADERTEST_NESTED__2_1_SOMEBOOL", "true")
	t.Setenv("CONFIGLOADERTEST_NESTED__2_1_SOME__STRING", "from env as well")
	t.Setenv("CONFIGLOADERTEST_NESTED__2_1_SOMEINT", "333")

	err = New(
		WithConfigFile(fileName),
		WithEnvPrefix("CONFIGLOADERTEST_"),
	).Load(&config)

	require.NoError(t, err)

	assert.Equal(t, "overridden by yaml file", config.SomeString) // yaml override
	assert.Equal(t, 42, config.SomeInt)                           // env override
	assert.True(t, config.SomeBool)                               // set by env

	assert.Equal(t, "from env", config.Nested1.SomeString) // set by env
	assert.Equal(t, 111, config.Nested1.SomeInt)           // set by env
	assert.True(t, config.Nested1.SomeBool)                // set by yaml
	assert.Equal(t, "bar", config.Nested1.Nested.Value)    // set by env

	assert.Equal(t, "from yaml", config.Nested2[0].SomeString) // set by yaml
	assert.Equal(t, 222, config.Nested2[0].SomeInt)            // set by env
	assert.True(t, config.Nested2[0].SomeBool)                 // set by env
	assert.Equal(t, "foo", config.Nested2[0].Nested.Value)     // set by env

	assert.Equal(t, "from env as well", config.Nested2[1].SomeString) // set by yaml
	assert.Equal(t, 333, config.Nested2[1].SomeInt)                   // set by env
	assert.True(t, config.Nested2[1].SomeBool)                        // set by env
	assert.Empty(t, config.Nested2[1].Nested.Value)
}
