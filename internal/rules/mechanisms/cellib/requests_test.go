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
	"net/http"
	"net/url"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
)

func TestRequests(t *testing.T) {
	t.Parallel()

	env, err := cel.NewEnv(
		Requests(),
		Urls(),
		Networks(),
	)
	require.NoError(t, err)

	rawURI := "http://localhost:8080/foo/bar?foo=bar&foo=baz&bar=foo"
	uri, err := url.Parse(rawURI)
	require.NoError(t, err)

	reqf := mocks.NewRequestFunctionsMock(t)
	reqf.EXPECT().Cookie("foo").Return("bar")
	reqf.EXPECT().Header("bar").Return("baz")
	reqf.EXPECT().Header("zab").Return("bar;charset=utf-8")
	reqf.EXPECT().Header("accept").Return("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	reqf.EXPECT().Body().Return(map[string]any{"foo": []any{"bar"}})

	req := &heimdall.Request{
		RequestFunctions: reqf,
		Method:           http.MethodHead,
		URL: &heimdall.URL{
			URL:      *uri,
			Captures: map[string]string{"foo": "bar"},
		},
		ClientIPAddresses: []string{"127.0.0.1"},
	}

	for _, tc := range []struct {
		expr string
	}{
		{expr: `Request.Method == "HEAD"`},
		{expr: `Request.URL.String() == "` + rawURI + `"`},
		{expr: `Request.URL.Captures.foo == "bar"`},
		{expr: `Request.URL.Query().bar == ["foo"]`},
		{expr: `Request.URL.Host == "localhost:8080"`},
		{expr: `Request.URL.Hostname() == "localhost"`},
		{expr: `Request.URL.Port() == "8080"`},
		{expr: `Request.Cookie("foo") == "bar"`},
		{expr: `Request.Header("bar") == "baz"`},
		{expr: `Request.Header("zab").contains("bar")`},
		{expr: `Request.Header("accept").matches("(text/html|application/xml)")`},
		{expr: `["text/html", "application/xml", "application/json"].exists(v, Request.Header("accept").contains(v))`},
		{expr: `Request.ClientIPAddresses in networks("127.0.0.0/24")`},
		{expr: `Request.Body().foo[0] == "bar"`},
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

			out, _, err := prg.Eval(map[string]any{"Request": req})
			require.NoError(t, err)
			require.Equal(t, true, out.Value()) //nolint:testifylint
		})
	}
}
