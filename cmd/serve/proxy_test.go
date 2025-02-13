// Copyright 2023-2025 Dimitrij Drus <dadrus@gmx.de>
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

package serve

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/cmd/flags"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestRunProxyMode(t *testing.T) {
	// this test verifies that all dependencies are resolved
	// and nothing has been forgotten
	port1, err := testsupport.GetFreePort()
	require.NoError(t, err)

	port2, err := testsupport.GetFreePort()
	require.NoError(t, err)

	t.Setenv("HEIMDALLCFG_SERVE_PORT", strconv.Itoa(port1))
	t.Setenv("HEIMDALLCFG_MANAGEMENT_PORT", strconv.Itoa(port2))

	cmd := NewProxyCommand()
	flags.RegisterGlobalFlags(cmd)

	err = cmd.ParseFlags([]string{"--" + flags.SkipAllSecurityEnforcement})
	require.NoError(t, err)

	go func() {
		err = cmd.Execute()
		assert.NoError(t, err)
	}()

	time.Sleep(500 * time.Millisecond)
}

func TestRunProxyModeFails(t *testing.T) {
	cmd := NewProxyCommand()
	flags.RegisterGlobalFlags(cmd)

	err := cmd.Execute()
	require.Error(t, err)
	require.ErrorIs(t, err, heimdall.ErrConfiguration)
	// secure config is enforcement, but not done
	require.Contains(t, err.Error(), "configuration is invalid")
}
