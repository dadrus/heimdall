package authenticators

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateAuthenticatorPrototype(t *testing.T) {
	t.Parallel()

	// there are seven authenticators implemented, which should have been registered
	require.Len(t, authenticatorTypeFactories, 7)

	for _, tc := range []struct {
		uc     string
		typ    string
		assert func(t *testing.T, err error, auth Authenticator)
	}{
		{
			uc:  "using known type",
			typ: AuthenticatorNoop,
			assert: func(t *testing.T, err error, auth Authenticator) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, &noopAuthenticator{}, auth)
			},
		},
		{
			uc:  "using unknown type",
			typ: "foo",
			assert: func(t *testing.T, err error, auth Authenticator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, ErrUnsupportedAuthenticatorType)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			auth, err := CreateAuthenticatorPrototype("foo", tc.typ, nil)

			// THEN
			tc.assert(t, err, auth)
		})
	}
}
