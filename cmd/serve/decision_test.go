// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
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

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestCreateDecisionApp(t *testing.T) {
	// this test verifies that all dependencies are resolved
	// and nothing has been forgotten
	port1, err := testsupport.GetFreePort()
	require.NoError(t, err)

	port2, err := testsupport.GetFreePort()
	require.NoError(t, err)

	t.Setenv("SERVE_DECISION_PORT", strconv.Itoa(port1))
	t.Setenv("SERVE_MANAGEMENT_PORT", strconv.Itoa(port2))

	_, err = createDecisionApp(&cobra.Command{})
	require.NoError(t, err)
}
