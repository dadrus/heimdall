// Copyright 2024 Dimitrij Drus <dadrus@gmx.de>
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
