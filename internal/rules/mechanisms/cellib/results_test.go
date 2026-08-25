// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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
	"net/http"
	"testing"

	"cel.dev/cel-go/cel"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
)

func TestResults(t *testing.T) {
	t.Parallel()

	env, err := cel.NewEnv(
		Results(),
		cel.Variable("Results", cel.MapType(cel.StringType, cel.DynType)),
	)
	require.NoError(t, err)

	headers := make(http.Header)
	headers.Set("X-My-Header", "baz")
	headers.Add("X-Multi-Header", "foo")
	headers.Add("X-Multi-Header", "bar")

	results := heimdall.Results{
		"foo": heimdall.NewResultWithHeaders(
			map[string]any{"baz": "bar"},
			headers,
		),
		"bar": heimdall.NewResult(map[string]any{"baz": "zab"}),
	}

	for _, tc := range []string{
		`Results.foo.Payload.baz == "bar"`,
		`Results.foo.Header("X-My-Header") == "baz"`,
		`Results.foo.Header("x-my-header") == "baz"`,
		`Results.foo.Header("X-Multi-Header") == "foo,bar"`,
		`Results.foo.Header("X-Missing") == ""`,
		`Results.bar.Payload.baz == "zab"`,
		`Results.bar.Header("X-My-Header") == ""`,
	} {
		t.Run(tc, func(t *testing.T) {
			ast, iss := env.Compile(tc)
			if iss != nil {
				require.NoError(t, iss.Err())
			}

			ast, iss = env.Check(ast)
			if iss != nil {
				require.NoError(t, iss.Err())
			}

			prg, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
			require.NoError(t, err)

			out, _, err := prg.Eval(map[string]any{"Results": results})
			require.NoError(t, err)
			require.Equal(t, true, out.Value()) //nolint:testifylint
		})
	}
}
