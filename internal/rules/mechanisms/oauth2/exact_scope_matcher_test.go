package oauth2

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExactScopeMatcherMatch(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc             string
		requiredScopes ExactScopeStrategyMatcher
		providedScopes []string
		assert         func(t *testing.T, err error)
	}{
		{
			uc:             "doesn't match if only first scope is present",
			requiredScopes: ExactScopeStrategyMatcher{"foo.bar.baz", "foo.bar"},
			providedScopes: []string{"foo.bar.baz"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			uc:             "doesn't match if only second scope is present",
			requiredScopes: ExactScopeStrategyMatcher{"foo.bar.baz", "foo.bar"},
			providedScopes: []string{"foo.bar"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			uc:             "matches when all required scopes are present",
			requiredScopes: ExactScopeStrategyMatcher{"foo.bar.baz", "foo.bar"},
			providedScopes: []string{"foo.bar.baz", "foo.bar"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc:             "matches when more than all required scopes are present",
			requiredScopes: ExactScopeStrategyMatcher{"foo.bar.baz", "foo.bar"},
			providedScopes: []string{"foo.bar.baz", "foo.bar", "baz.baz"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc:             "doesn't match when no required scopes are present",
			requiredScopes: ExactScopeStrategyMatcher{"foo.bar.baz", "foo.bar"},
			providedScopes: []string{},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			uc:             "doesn't match not included scope",
			requiredScopes: ExactScopeStrategyMatcher{"foo.bar.baz", "foo.bar"},
			providedScopes: []string{"baz.baz"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			uc:             "matches if no required scopes are defined",
			requiredScopes: ExactScopeStrategyMatcher{},
			providedScopes: []string{"baz.baz"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			err := tc.requiredScopes.Match(tc.providedScopes)

			// THEN
			tc.assert(t, err)
		})
	}
}
