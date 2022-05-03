package authorizers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
)

func TestCreateAuthorizerPrototypeUsingKnowType(t *testing.T) {
	t.Parallel()

	// there are 3 authorizers implemented, which should have been registered
	require.Len(t, authorizerTypeFactories, 4)

	for _, tc := range []struct {
		uc     string
		typ    config.PipelineObjectType
		assert func(t *testing.T, err error, auth Authorizer)
	}{
		{
			uc:  "using known type",
			typ: config.POTAllow,
			assert: func(t *testing.T, err error, auth Authorizer) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, &allowAuthorizer{}, auth)
			},
		},
		{
			uc:  "using unknown type",
			typ: config.POTJwt,
			assert: func(t *testing.T, err error, auth Authorizer) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, ErrUnsupportedAuthorizerType)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			auth, err := CreateAuthorizerPrototype("foo", tc.typ, nil)

			// THEN
			tc.assert(t, err, auth)
		})
	}
}
