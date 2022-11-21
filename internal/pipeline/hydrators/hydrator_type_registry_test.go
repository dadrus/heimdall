package hydrators

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
)

func TestCreateHydratorPrototype(t *testing.T) {
	t.Parallel()

	// there are 3 error handlers implemented, which should have been registered
	require.Len(t, hydratorTypeFactories, 1)

	for _, tc := range []struct {
		uc     string
		typ    config.PipelineHandlerType
		assert func(t *testing.T, err error, hydrator Hydrator)
	}{
		{
			uc:  "using known type",
			typ: config.POTGeneric,
			assert: func(t *testing.T, err error, hydrator Hydrator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
			},
		},
		{
			uc:  "using unknown type",
			typ: config.POTDeny,
			assert: func(t *testing.T, err error, hydrator Hydrator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, ErrUnsupportedHydratorType)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			errorHandler, err := CreateHydratorPrototype("foo", tc.typ, nil)

			// THEN
			tc.assert(t, err, errorHandler)
		})
	}
}
