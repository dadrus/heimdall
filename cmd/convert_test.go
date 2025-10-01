package cmd

import (
	"testing"

	"github.com/dadrus/heimdall/cmd/flags"
	"github.com/stretchr/testify/assert"
)

func TestNewConvertCmd(t *testing.T) {
	t.Parallel()

	// WHEN
	cmd := newConvertCmd()

	// THEN
	assert.Equal(t, "convert", cmd.Use)
	assert.NotEmpty(t, cmd.Short)

	// Peek just some of the global flags. Should not be present
	configFlag := cmd.PersistentFlags().Lookup(flags.Config)
	assert.Nil(t, configFlag)

	commands := cmd.Commands()
	assert.Len(t, commands, 1)
	assert.Contains(t, commands[0].Use, "rules")
}
