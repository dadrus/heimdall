package authorizers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateAuthorizerPrototypeUsingKnowType(t *testing.T) {
	t.Parallel()

	// there are 5 authorizers implemented, which should have been registered
	require.Len(t, authorizerTypeFactories, 4)

	for _, tc := range []struct {
		uc     string
		typ    string
		assert func(t *testing.T, err error, auth Authorizer)
	}{
		{
			uc:  "using known type",
			typ: AuthorizerAllow,
			assert: func(t *testing.T, err error, auth Authorizer) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, &allowAuthorizer{}, auth)
			},
		},
		{
			uc:  "using unknown type",
			typ: "foo",
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
