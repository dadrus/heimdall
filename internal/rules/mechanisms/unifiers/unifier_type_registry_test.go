package unifiers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateUnifierPrototype(t *testing.T) {
	t.Parallel()

	// there are 4 unifiers implemented, which should have been registered
	require.Len(t, typeFactories, 4)

	for _, tc := range []struct {
		uc     string
		typ    string
		assert func(t *testing.T, err error, unifier Unifier)
	}{
		{
			uc:  "using known type",
			typ: UnifierNoop,
			assert: func(t *testing.T, err error, unifier Unifier) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, &noopUnifier{}, unifier)
			},
		},
		{
			uc:  "using unknown type",
			typ: "foo",
			assert: func(t *testing.T, err error, unifier Unifier) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, ErrUnsupportedUnifierType)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			unifier, err := CreateUnifierPrototype("foo", tc.typ, nil)

			// THEN
			tc.assert(t, err, unifier)
		})
	}
}
