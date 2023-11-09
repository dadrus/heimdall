package cellib

import (
	"net/url"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/stretchr/testify/require"
)

func TestUrls(t *testing.T) {
	t.Parallel()

	env, err := cel.NewEnv(
		cel.Variable("uri", cel.DynType),
		Urls(),
	)
	require.NoError(t, err)

	rawURI := "http://localhost/foo/bar?foo=bar&foo=baz&bar=foo"
	uri, err := url.Parse("http://localhost/foo/bar?foo=bar&foo=baz&bar=foo")
	require.NoError(t, err)

	for _, tc := range []struct {
		expr string
	}{
		{expr: `uri.String() == "` + rawURI + `"`},
		{expr: `uri.Query() == {"foo":["bar", "baz"], "bar": ["foo"]}`},
		{expr: `uri.Query().bar == ["foo"]`},
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

			out, _, err := prg.Eval(map[string]any{"uri": uri})
			require.NoError(t, err)
			require.Equal(t, true, out.Value()) //nolint:testifylint
		})
	}
}
