// Copyright 2022-2025 Dimitrij Drus <dadrus@gmx.de>
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
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/cmd/flags"
	"github.com/dadrus/heimdall/internal/config"
)

func TestCreateApp(t *testing.T) {
	t.Parallel()

	cmd := &cobra.Command{}
	flags.RegisterGlobalFlags(cmd)

	err := cmd.ParseFlags([]string{"--" + flags.SkipAllSecurityEnforcement})
	require.NoError(t, err)

	app, err := createApp(cmd, fx.Supply(config.DecisionMode))
	require.NoError(t, err)
	require.NotNil(t, app)
}
