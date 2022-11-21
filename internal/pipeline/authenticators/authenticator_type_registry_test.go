package authenticators

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
)

func TestCreateAuthenticatorPrototype(t *testing.T) {
	t.Parallel()

	// there are seven authenticators implemented, which should have been registered
	require.Len(t, authenticatorTypeFactories, 7)

	for _, tc := range []struct {
		uc     string
		typ    config.PipelineHandlerType
		assert func(t *testing.T, err error, auth Authenticator)
	}{
		{
			uc:  "using known type",
			typ: config.POTNoop,
			assert: func(t *testing.T, err error, auth Authenticator) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, &noopAuthenticator{}, auth)
			},
		},
		{
			uc:  "using unknown type",
			typ: config.POTDeny,
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
