package oauth2

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIntrospectionResponseValidate(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		tokenType TokenType
		resp      IntrospectionResponse
		exp       Expectation
		assert    func(t *testing.T, err error)
	}{
		"token is not active": {
			resp: IntrospectionResponse{
				Active: false,
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "token is not active")
			},
		},
		"contents validation fails": {
			resp: IntrospectionResponse{
				Active: true,
				Claims: Claims{
					Issuer: "foo",
				},
			},
			exp: Expectation{
				TrustedIssuers: []string{"bar"},
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "issuer foo is not trusted")
			},
		},
		"contents validation succeeds": {
			resp: IntrospectionResponse{
				Active: true,
				Claims: Claims{
					Issuer:    "foo",
					TokenType: TypeBearer,
				},
			},
			exp: Expectation{
				TrustedIssuers: []string{"foo"},
				ScopesMatcher:  NoopMatcher{},
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			err := tc.resp.Validate(nil, tc.tokenType, "", tc.exp)

			tc.assert(t, err)
		})
	}
}
