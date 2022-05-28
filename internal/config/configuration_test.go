package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewConfigurationFromStructWithDefaultsOnly(t *testing.T) {
	// WHEN
	config, err := NewConfiguration("")

	// THEN
	require.NoError(t, err)
	require.Equal(t, defaultConfig, config)
}
