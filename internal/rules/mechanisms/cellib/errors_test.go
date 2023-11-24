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
		Errors(),
	)
	require.NoError(t, err)

	for _, tc := range []struct {
		expr string
	}{
		{expr: `type(Error) == authorization_error`},
		{expr: `authorization_error == type(Error)`},
		{expr: `authorization_error != Error`},
		{expr: `Error != authorization_error`},
		{expr: `type(Error) == authentication_error`},
		{expr: `type(Error) == internal_error`},
		{expr: `type(Error) in [internal_error, authorization_error, authentication_error]`},
		{expr: `type(Error) != precondition_error`},
		{expr: `precondition_error != type(Error)`},
		{expr: `type(Error) != communication_error`},
		{expr: `internal_error == internal_error`},
		{expr: `Error.Source == "test"`},
		{expr: `Error == Error`},
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
