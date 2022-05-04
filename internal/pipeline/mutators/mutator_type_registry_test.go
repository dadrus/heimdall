package mutators

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
)

func TestCreateMutatorPrototype(t *testing.T) {
	t.Parallel()

	// there are 4 mutators implemented, which should have been registered
	require.Len(t, mutatorTypeFactories, 4)

	for _, tc := range []struct {
		uc     string
		typ    config.PipelineObjectType
		assert func(t *testing.T, err error, mutator Mutator)
	}{
		{
			uc:  "using known type",
			typ: config.POTNoop,
			assert: func(t *testing.T, err error, mutator Mutator) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, &noopMutator{}, mutator)
			},
		},
		{
			uc:  "using unknown type",
			typ: config.POTDeny,
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
