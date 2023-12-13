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

package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
)

func TestValidateNotExistingConfigFile(t *testing.T) {
	t.Parallel()

	err := ValidateConfig("foo.bar")

	require.Error(t, err)
	require.ErrorIs(t, err, heimdall.ErrConfiguration)
	assert.Contains(t, err.Error(), "read config file")
}

func TestValidateNotReadableConfigFile(t *testing.T) {
	t.Parallel()

	tmpFile, err := os.CreateTemp("", "test-config-")
	require.NoError(t, err)

	require.NoError(t, tmpFile.Chmod(0o200))

	defer os.Remove(tmpFile.Name())

	err = ValidateConfig(tmpFile.Name())

	require.Error(t, err)
	require.ErrorIs(t, err, heimdall.ErrConfiguration)
	assert.Contains(t, err.Error(), "read config file")
}

func TestValidateEmptyConfigFile(t *testing.T) {
	t.Parallel()

	tmpFile, err := os.CreateTemp("", "test-config-")
	require.NoError(t, err)

	defer os.Remove(tmpFile.Name())

	err = ValidateConfig(tmpFile.Name())

	require.Error(t, err)
	require.ErrorIs(t, err, heimdall.ErrConfiguration)
	assert.Contains(t, err.Error(), "empty")
}

func TestValidateConfigFileWithInvalidYAMLContent(t *testing.T) {
	t.Parallel()

	tmpFile, err := os.CreateTemp("", "test-config-")
	require.NoError(t, err)

	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(`foobar`)
	require.NoError(t, err)

	err = ValidateConfig(tmpFile.Name())

	require.Error(t, err)
	require.ErrorIs(t, err, heimdall.ErrConfiguration)
	assert.Contains(t, err.Error(), "parse config")
}

func TestValidateConfigFileWithValidYAMLContentButFailingSchemaValidation(t *testing.T) {
	t.Parallel()

	tmpFile, err := os.CreateTemp("", "test-config-")
	require.NoError(t, err)

	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(`foo: bar`)
	require.NoError(t, err)

	err = ValidateConfig(tmpFile.Name())

	require.Error(t, err)
	require.ErrorIs(t, err, heimdall.ErrConfiguration)
	assert.Contains(t, err.Error(), "validate")
}

func TestValidateValidConfigFile(t *testing.T) {
	t.Parallel()

	err := ValidateConfig("./test_data/test_config.yaml")

	require.NoError(t, err)
}
