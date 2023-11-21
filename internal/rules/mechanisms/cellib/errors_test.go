package cellib

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type idProvider struct {
	id string
}

func (i idProvider) ID() string { return i.id }

func TestErrors(t *testing.T) {
	t.Parallel()

	env, err := cel.NewEnv(
		cel.Variable("Error", cel.DynType),
		Errors(),
	)
	require.NoError(t, err)

	for _, tc := range []struct {
		expr string
	}{
		{expr: `Error.Is("authorization_error")`},
		{expr: `Error.Is("authentication_error")`},
		{expr: `Error.Is("internal_error")`},
		{expr: `Error.Is("precondition_error")`},
		{expr: `!Error.Is("unknown_error")`},
		{expr: `Error.Source() == "test"`},
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

			causeErr := errorchain.New(heimdall.ErrAuthorization).
				CausedBy(errorchain.New(heimdall.ErrArgument)).
				CausedBy(errorchain.New(heimdall.ErrAuthentication)).
				CausedBy(errorchain.New(heimdall.ErrConfiguration)).
				CausedBy(errorchain.New(heimdall.ErrInternal)).
				WithErrorContext(idProvider{id: "test"})

			out, _, err := prg.Eval(map[string]any{"Error": WrapError(causeErr)})
			require.NoError(t, err)
			require.Equal(t, true, out.Value()) //nolint:testifylint
		})
	}
}
