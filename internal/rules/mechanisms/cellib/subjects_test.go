package cellib

import (
	"reflect"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/rules/mechanisms/identity"
)

func TestCELSubjectExpressions(t *testing.T) {
	t.Parallel()

	env, err := cel.NewEnv(Subjects())
	require.NoError(t, err)

	for _, tc := range []struct {
		expr   string
		expErr string
	}{
		{expr: `Subject == Subject`},
		{expr: `type(Subject) == type(Subject)`},
		{expr: `type(Subject.default) == type(Subject.default)`},
		{expr: `Subject.default == Subject.default`},
		{expr: `Subject.default != Subject`},
		{expr: `Subject != Subject.default`},
		{expr: `Subject.ID == "foo"`},
		{expr: `Subject.Attributes.baz == "foo"`},
		{expr: `Subject.default.ID == "foo"`},
		{expr: `Subject.default.Attributes.baz == "foo"`},
		{expr: `Subject.other.ID == "bar"`},
		{expr: `Subject.other.Attributes.foo == "bar"`},
		{expr: `Subject.bla == "bar"`, expErr: "unknown field: bla"},
		{expr: `Subject.default.bla == "bar"`, expErr: "unknown field: bla"},
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
			if len(tc.expErr) != 0 {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.expErr)
			} else {
				require.NoError(t, err)
				require.Equal(t, true, out.Value()) //nolint:testifylint
			}
		})
	}
}

func TestCELSubjectTypeAndValue(t *testing.T) {
	t.Parallel()

	sub := identity.Subject{"default": &identity.Principal{ID: "foo"}}
	wrapper := WrapSubject(sub)

	require.Equal(t, subjectType, wrapper.Type())
	require.Equal(t, sub, wrapper.Value())
}

func TestCELSubjectTypeConvertToNative(t *testing.T) {
	t.Parallel()

	sub := identity.Subject{"default": &identity.Principal{ID: "foo"}}
	wrapper := WrapSubject(sub)

	for uc, tc := range map[string]struct {
		typ    reflect.Type
		expErr string
		expObj any
	}{
		"conversion to Subject type": {
			typ:    reflect.TypeOf(identity.Subject{}),
			expObj: sub,
		},
		"conversion to string type": {
			typ:    reflect.TypeOf(""),
			expErr: "from 'Subject' to 'string'",
		},
	} {
		t.Run(uc, func(t *testing.T) {
			native, err := wrapper.ConvertToNative(tc.typ)

			if len(tc.expErr) != 0 {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.expErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expObj, native)
			}
		})
	}
}

func TestCELPrincipalTypeAndValue(t *testing.T) {
	t.Parallel()

	principal := &identity.Principal{ID: "foo"}
	wrapper := celPrincipal{principal: principal}

	require.Equal(t, principalType, wrapper.Type())
	require.Equal(t, principal, wrapper.Value())
}

func TestCELPrincipalTypeConvertToNative(t *testing.T) {
	t.Parallel()

	principal := &identity.Principal{ID: "foo"}
	wrapper := celPrincipal{principal: principal}

	for uc, tc := range map[string]struct {
		typ    reflect.Type
		expErr string
		expObj any
	}{
		"conversion to Principal type": {
			typ:    reflect.TypeOf(&identity.Principal{}),
			expObj: principal,
		},
		"conversion to string type": {
			typ:    reflect.TypeOf(""),
			expErr: "from 'Principal' to 'string'",
		},
	} {
		t.Run(uc, func(t *testing.T) {
			native, err := wrapper.ConvertToNative(tc.typ)

			if len(tc.expErr) != 0 {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.expErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expObj, native)
			}
		})
	}
}
