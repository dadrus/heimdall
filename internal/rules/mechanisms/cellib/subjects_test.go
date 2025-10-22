package cellib

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/rules/mechanisms/identity"
)

func TestSubjects(t *testing.T) {
	t.Parallel()

	env, err := cel.NewEnv(Subjects())
	require.NoError(t, err)

	for _, tc := range []string{
		`Subject == Subject`,
		`Subject.ID == "foo"`,
		`Subject.Attributes.baz == "foo"`,
		`Subject.default.ID == "foo"`,
		`Subject.default.Attributes.baz == "foo"`,
		`Subject.other.ID == "bar"`,
		`Subject.other.Attributes.foo == "bar"`,
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

			sub := identity.Subject{
				"default": &identity.Principal{
					ID:         "foo",
					Attributes: map[string]any{"baz": "foo"},
				},
				"other": &identity.Principal{
					ID:         "bar",
					Attributes: map[string]any{"foo": "bar"},
				},
			}

			out, _, err := prg.Eval(map[string]any{"Subject": WrapSubject(sub)})
			require.NoError(t, err)
			require.Equal(t, true, out.Value()) //nolint:testifylint
		})
	}
}
