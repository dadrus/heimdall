package cellib

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLists(t *testing.T) {
	t.Parallel()

	env, err := cel.NewEnv(Lists())
	require.NoError(t, err)

	for _, tc := range []struct {
		expr string
		err  string
	}{
		{expr: `[1,2,3,4].last() == 4`},
		{expr: `[1,2,3,4].at(0) == 1`},
		{expr: `[1,2,3,4].at(2) == 3`},
		{expr: `[1,2,3,4].at(-1) == 4`},
		{expr: `[1,2,3,4].at(-3) == 2`},
		{expr: `[1,2,3,4].at(6)`, err: "cannot at(6), position is outside of the list boundaries"},
		{expr: `[1,2,3,4].at(-6)`, err: "cannot at(-6), position is outside of the list boundaries"},
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
			if len(tc.err) != 0 {
				require.Error(t, err)
				assert.Equal(t, tc.err, err.Error())
			} else {
				require.Equal(t, true, out.Value()) //nolint:testifylint
			}
		})
	}
}
