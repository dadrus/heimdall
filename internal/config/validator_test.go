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

	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
)

func TestValidateEmptyConfig(t *testing.T) {
	t.Parallel()

	tmpFile, err := os.CreateTemp(t.TempDir(), "test-config-")
	require.NoError(t, err)

	err = ValidateConfigSchema(tmpFile)

	require.Error(t, err)
	require.ErrorIs(t, err, heimdall.ErrConfiguration)
	require.ErrorContains(t, err, "EOF")
}

func TestValidateConfigWithInvalidYAMLContent(t *testing.T) {
	t.Parallel()

	tmpFile, err := os.CreateTemp(t.TempDir(), "test-config-")
	require.NoError(t, err)

	_, err = tmpFile.WriteString(`foobar`)
	require.NoError(t, err)

	err = ValidateConfigSchema(tmpFile)

	require.Error(t, err)
	require.ErrorIs(t, err, heimdall.ErrConfiguration)
	require.ErrorContains(t, err, "parse config")
}

func TestValidateConfigWithValidYAMLContentButFailingSchemaValidation(t *testing.T) {
	t.Parallel()

	tmpFile, err := os.CreateTemp(t.TempDir(), "test-config-")
	require.NoError(t, err)

	_, err = tmpFile.WriteString(`foo: bar`)
	require.NoError(t, err)

	_, err = tmpFile.Seek(0, 0)
	require.NoError(t, err)

	err = ValidateConfigSchema(tmpFile)

	require.Error(t, err)
	require.ErrorIs(t, err, heimdall.ErrConfiguration)
	require.ErrorContains(t, err, "'foo' not allowed")
}

func TestValidateValidConfigFile(t *testing.T) {
	t.Parallel()

	file, err := os.Open("./test_data/test_config.yaml")
	require.NoError(t, err)

	err = ValidateConfigSchema(file)

	require.NoError(t, err)
}
