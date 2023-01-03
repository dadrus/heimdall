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

package logging

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
)

func redirectStdout(exec func()) ([]byte, error) {
	tempFile, err := os.CreateTemp("", "logconfig-test")
	if err != nil {
		return nil, err
	}

	defer tempFile.Close()

	fileName := tempFile.Name()
	defer os.Remove(fileName) // Ignore error

	origStdout := os.Stdout
	os.Stdout = tempFile

	defer func() {
		os.Stdout = origStdout
	}()

	exec()

	return os.ReadFile(fileName)
}

func TestNewTextLogger(t *testing.T) {
	// WHEN
	data, err := redirectStdout(func() {
		logger := NewLogger(config.LoggingConfig{Format: config.LogTextFormat})

		logger.Info().Msg("Hello Heimdall")
	})

	require.NoError(t, err)
	assert.NotContains(t, string(data), "{")
	assert.NotContains(t, string(data), "short_message")
	assert.Contains(t, string(data), "Hello Heimdall")
}

func TestNewGelfLogger(t *testing.T) {
	// WHEN
	data, err := redirectStdout(func() {
		logger := NewLogger(config.LoggingConfig{Format: config.LogGelfFormat})

		logger.Info().Msg("Hello Heimdall")
	})

	require.NoError(t, err)
	assert.Contains(t, string(data), `{`)
	assert.Contains(t, string(data), `}`)
	assert.Contains(t, string(data), `"_level_name":"INFO"`)
	assert.Contains(t, string(data), `"version":"1.1"`)
	assert.Contains(t, string(data), `"host"`)
	assert.Contains(t, string(data), `"timestamp"`)
	assert.Contains(t, string(data), `"level":6`)
	assert.Contains(t, string(data), `"short_message":"Hello Heimdall"`)
}
