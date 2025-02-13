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

func TestNewServeCmd(t *testing.T) {
	t.Parallel()

	// WHEN
	cmd := newServeCmd()

	// THEN
	assert.Equal(t, "serve", cmd.Use)
	assert.NotEmpty(t, cmd.Short)

	// peek just some of the global flags
	configFlag := cmd.PersistentFlags().Lookup(flags.Config)
	assert.NotNil(t, configFlag)
	assert.Equal(t, "c", configFlag.Shorthand)
	assert.Empty(t, configFlag.DefValue)
	assert.NotEmpty(t, configFlag.Usage)

	skipSecureDefaultRuleEnforcementFlag := cmd.PersistentFlags().Lookup(flags.SkipSecureDefaultRuleEnforcement)
	assert.NotNil(t, skipSecureDefaultRuleEnforcementFlag)
	assert.Empty(t, skipSecureDefaultRuleEnforcementFlag.Shorthand)
	assert.Equal(t, "false", skipSecureDefaultRuleEnforcementFlag.DefValue)
	assert.NotEmpty(t, skipSecureDefaultRuleEnforcementFlag.Usage)

	commands := cmd.Commands()
	assert.Len(t, commands, 2)
	assert.Contains(t, commands[0].Use, "decision")
	assert.Contains(t, commands[1].Use, "proxy")
}
