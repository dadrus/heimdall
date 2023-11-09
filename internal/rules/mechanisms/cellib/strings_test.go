package cellib

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/stretchr/testify/require"
)

func TestStrings(t *testing.T) {
	t.Parallel()

	env, err := cel.NewEnv(Strings())
	require.NoError(t, err)

	for _, tc := range []struct {
		expr string
	}{
		{expr: `"abcd1234".regexFind("[a-zA-Z][1-9]") == "d1"`},
		{expr: `"123456789".regexFindAll("[2,4,6,8]") == ["2","4","6","8"]`},
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

			out, _, err := prg.Eval(cel.NoVars())
			require.NoError(t, err)
			require.Equal(t, true, out.Value()) //nolint:testifylint
		})
	}
}
