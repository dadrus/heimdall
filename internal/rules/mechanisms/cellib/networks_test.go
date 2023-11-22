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
		{expr: `"192.168.1.10" in network("192.168.1.0/24")`},
		{expr: `["192.168.1.10", "192.168.1.12"] in network("192.168.1.0/24")`},
		{expr: `"192.168.1.10" in networks(["192.168.1.0/24"])`},
		{expr: `["192.168.1.10", "192.168.1.12"].all(ip, ip in networks(["192.168.1.0/24"]))`},
		{expr: `["192.168.1.10", "192.168.1.12"] in networks(["192.168.1.0/24"])`},
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
