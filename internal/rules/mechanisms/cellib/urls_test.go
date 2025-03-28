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
	"net/url"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
)

func TestUrls(t *testing.T) {
	t.Parallel()

	env, err := cel.NewEnv(
		cel.Variable("uri", cel.DynType),
		Urls(),
	)
	require.NoError(t, err)

	rawURI := "http://localhost:8080/foo/bar?foo=bar&foo=baz&bar=foo"
	uri, err := url.Parse(rawURI)
	require.NoError(t, err)

	for _, tc := range []string{
		`uri.String() == "` + rawURI + `"`,
		`uri.Query() == {"foo":["bar", "baz"], "bar": ["foo"]}`,
		`uri.Query().bar == ["foo"]`,
		`uri.Host == "localhost:8080"`,
		`uri.Hostname() == "localhost"`,
		`uri.Port() == "8080"`,
		`uri.Captures.zab == "baz"`,
		`uri.Path == "/foo/bar"`,
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

			out, _, err := prg.Eval(map[string]any{"uri": &heimdall.URL{URL: *uri, Captures: map[string]string{"zab": "baz"}}})
			require.NoError(t, err)
			require.Equal(t, true, out.Value()) //nolint:testifylint
		})
	}
}
