package config

import (
	"io/ioutil"
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
	assert.ErrorIs(t, err, heimdall.ErrConfiguration)
	assert.Contains(t, err.Error(), "read config file")
}

func TestValidateNotReadableConfigFile(t *testing.T) {
	t.Parallel()

	tmpFile, err := ioutil.TempFile("", "test-config-")
	require.NoError(t, err)

	require.NoError(t, tmpFile.Chmod(0o200))

	defer os.Remove(tmpFile.Name())

	err = ValidateConfig(tmpFile.Name())

	require.Error(t, err)
	assert.ErrorIs(t, err, heimdall.ErrConfiguration)
	assert.Contains(t, err.Error(), "read config file")
}

func TestValidateEmptyConfigFile(t *testing.T) {
	t.Parallel()

	tmpFile, err := ioutil.TempFile("", "test-config-")
	require.NoError(t, err)

	defer os.Remove(tmpFile.Name())

	err = ValidateConfig(tmpFile.Name())

	require.Error(t, err)
	assert.ErrorIs(t, err, heimdall.ErrConfiguration)
	assert.Contains(t, err.Error(), "empty")
}

func TestValidateConfigFileWithInvalidYAMLContent(t *testing.T) {
	t.Parallel()

	tmpFile, err := ioutil.TempFile("", "test-config-")
	require.NoError(t, err)

	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.Write([]byte(`foobar`))
	require.NoError(t, err)

	err = ValidateConfig(tmpFile.Name())

	require.Error(t, err)
	assert.ErrorIs(t, err, heimdall.ErrConfiguration)
	assert.Contains(t, err.Error(), "parse config")
}

func TestValidateConfigFileWithValidYAMLContentButFailingSchemaValidation(t *testing.T) {
	t.Parallel()

	tmpFile, err := ioutil.TempFile("", "test-config-")
	require.NoError(t, err)

	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.Write([]byte(`foo: bar`))
	require.NoError(t, err)

	err = ValidateConfig(tmpFile.Name())

	require.Error(t, err)
	assert.ErrorIs(t, err, heimdall.ErrConfiguration)
	assert.Contains(t, err.Error(), "validate")
}

func TestValidateValidConfigFile(t *testing.T) {
	t.Parallel()

	err := ValidateConfig("./test_data/test_config.yaml")

	require.NoError(t, err)
}
