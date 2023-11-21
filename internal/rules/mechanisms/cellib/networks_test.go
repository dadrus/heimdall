package cellib

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
)

func TestNetworks(t *testing.T) {
	t.Parallel()

	env, err := cel.NewEnv(
		cel.Variable("req", cel.DynType),
		Networks(),
	)
	require.NoError(t, err)

	req := &heimdall.Request{
		ClientIP: []string{"192.168.1.10", "192.168.1.11", "192.168.1.12"},
	}

	for _, tc := range []struct {
		expr string
	}{
		{expr: `network("192.168.1.0/24").Contains("192.168.1.10")`},
		{expr: `req.ClientIP.all(ip, network("192.168.1.0/24").Contains(ip))`},
		{expr: `network("192.168.1.0/24").ContainsAll(req.ClientIP)`},
		{expr: `networks(["192.168.1.0/24"]).Contain("192.168.1.10")`},
		{expr: `req.ClientIP.all(ip, networks(["192.168.1.0/24"]).Contain(ip))`},
		{expr: `networks(["192.168.1.0/24"]).ContainAll(req.ClientIP)`},
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

			out, _, err := prg.Eval(map[string]any{"req": req})
			require.NoError(t, err)
			require.Equal(t, true, out.Value()) //nolint:testifylint
		})
	}
}
