package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewConfigurationFromStructWithDefaultsOnly(t *testing.T) {
	// WHEN
	config, err := NewConfiguration("HEIMDALLCFG_", "")

	// THEN
	require.NoError(t, err)
	require.Equal(t, defaultConfig, config)
}

func TestNewConfigurationWithConfigFile(t *testing.T) {
	// WHEN
	config, err := NewConfiguration("HEIMDALLCFG_", "./test_data/test_config.yaml")

	// THEN
	require.NoError(t, err)
	assert.NotEqual(t, defaultConfig, config)
}
