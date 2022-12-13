package contextualizers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
)

func TestCreateContextualzerPrototype(t *testing.T) {
	t.Parallel()

	// there are 3 error handlers implemented, which should have been registered
	require.Len(t, typeFactories, 1)

	for _, tc := range []struct {
		uc     string
		typ    string
		assert func(t *testing.T, err error, contextualizer Contextualizer)
	}{
		{
			uc:  "using known type",
			typ: ContextualizerGeneric,
			assert: func(t *testing.T, err error, _ Contextualizer) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
			},
		},
		{
			uc:  "using unknown type",
			typ: "foo",
			assert: func(t *testing.T, err error, _ Contextualizer) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, ErrUnsupportedContextualizerType)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			errorHandler, err := CreateContextualizerPrototype("foo", tc.typ, nil)

			// THEN
			tc.assert(t, err, errorHandler)
		})
	}
}
