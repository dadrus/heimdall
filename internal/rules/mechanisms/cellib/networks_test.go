// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
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

package cellib

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/stretchr/testify/require"
)

func TestNetworks(t *testing.T) {
	t.Parallel()

	env, err := cel.NewEnv(
		Networks(),
	)
	require.NoError(t, err)

	for _, tc := range []struct {
		expr string
	}{
		{expr: `"192.168.1.10" in networks("192.168.1.0/24")`},
		{expr: `["192.168.1.10"].all(ip, ip in networks("192.168.1.0/24"))`},
		{expr: `!["10.0.1.1"].exists(ip, ip in networks("192.168.1.0/24"))`},
		{expr: `["192.168.1.10", "192.168.1.12"] in networks(["192.168.1.0/24"])`},
		{expr: `["192.168.1.10", "10.0.1.1"].all(ip, ip in networks(["192.168.1.0/24", "10.0.0.0/16"]))`},
		{expr: `["192.168.1.10", "10.0.1.1"].exists(ip, ip in networks(["10.0.0.0/16"]))`},
	} {
		t.Run(tc.expr, func(t *testing.T) {
			ast, iss := env.Compile(tc.expr)
			if iss != nil {
				require.NoError(t, iss.Err())
			}

			ast, iss = env.Check(ast)
			if iss != nil {
				require.NoError(t, iss.Err())
			}

			prg, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
			require.NoError(t, err)

			out, _, err := prg.Eval(map[string]any{})
			require.NoError(t, err)
			require.Equal(t, true, out.Value()) //nolint:testifylint
		})
	}
}
