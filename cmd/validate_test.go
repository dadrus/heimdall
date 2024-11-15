package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dadrus/heimdall/cmd/flags"
)

func TestNewValidateCmd(t *testing.T) {
	t.Parallel()

	// WHEN
	cmd := newValidateCmd()

	// THEN
	assert.Equal(t, "validate", cmd.Use)
	assert.NotEmpty(t, cmd.Short)

	configFlag := cmd.PersistentFlags().Lookup(flags.Config)
	assert.NotNil(t, configFlag)
	assert.Equal(t, "c", configFlag.Shorthand)
	assert.Empty(t, configFlag.DefValue)
	assert.NotEmpty(t, configFlag.Usage)

	envPrefixFlag := cmd.PersistentFlags().Lookup(flags.EnvironmentConfigPrefix)
	assert.NotNil(t, envPrefixFlag)
	assert.Empty(t, envPrefixFlag.Shorthand)
	assert.Equal(t, "HEIMDALLCFG_", envPrefixFlag.DefValue)
	assert.NotEmpty(t, envPrefixFlag.Usage)

	commands := cmd.Commands()
	assert.Len(t, commands, 2)
	assert.Contains(t, commands[0].Use, "config")
	assert.Contains(t, commands[1].Use, "rules")
}
