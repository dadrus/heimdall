package errorhandlers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
)

func TestCreateErrorHandlerPrototypePrototype(t *testing.T) {
	t.Parallel()

	// there are 3 error handlers implemented, which should have been registered
	require.Len(t, errorHandlerTypeFactories, 3)

	for _, tc := range []struct {
		uc     string
		typ    config.PipelineHandlerType
		assert func(t *testing.T, err error, errorHandler ErrorHandler)
	}{
		{
			uc:  "using known type",
			typ: config.POTDefault,
			assert: func(t *testing.T, err error, errorHandler ErrorHandler) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, &defaultErrorHandler{}, errorHandler)
			},
		},
		{
			uc:  "using unknown type",
			typ: config.POTDeny,
			assert: func(t *testing.T, err error, errorHandler ErrorHandler) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, ErrUnsupportedErrorHandlerType)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			errorHandler, err := CreateErrorHandlerPrototype("foo", tc.typ, nil)

			// THEN
			tc.assert(t, err, errorHandler)
		})
	}
}
