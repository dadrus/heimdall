package logging

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
)

func redirStdout(exec func()) ([]byte, error) {
	tempFile, err := ioutil.TempFile("", "logconfig-test")
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

	return ioutil.ReadFile(fileName)
}

func TestNewTextLogger(t *testing.T) {
	// WHEN
	data, err := redirStdout(func() {
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
	data, err := redirStdout(func() {
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
