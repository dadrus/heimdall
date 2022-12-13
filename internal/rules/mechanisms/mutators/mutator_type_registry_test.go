package mutators

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateMutatorPrototype(t *testing.T) {
	t.Parallel()

	// there are 4 mutators implemented, which should have been registered
	require.Len(t, mutatorTypeFactories, 4)

	for _, tc := range []struct {
		uc     string
		typ    string
		assert func(t *testing.T, err error, mutator Mutator)
	}{
		{
			uc:  "using known type",
			typ: MutatorNoop,
			assert: func(t *testing.T, err error, mutator Mutator) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, &noopMutator{}, mutator)
			},
		},
		{
			uc:  "using unknown type",
			typ: "foo",
			assert: func(t *testing.T, err error, mutator Mutator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, ErrUnsupportedMutatorType)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			mutator, err := CreateMutatorPrototype("foo", tc.typ, nil)

			// THEN
			tc.assert(t, err, mutator)
		})
	}
}
