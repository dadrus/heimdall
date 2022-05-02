package oauth2

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExactScopeMatcherMatch(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc      string
		matcher ExactScopeStrategyMatcher
		scopes  []string
		assert  func(t *testing.T, err error)
	}{
		{
			uc:      "doesn't match if only first scope is present",
			matcher: ExactScopeStrategyMatcher{"foo.bar.baz", "foo.bar"},
			scopes:  []string{"foo.bar.baz"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			uc:      "doesn't match if only second scope is present",
			matcher: ExactScopeStrategyMatcher{"foo.bar.baz", "foo.bar"},
			scopes:  []string{"foo.bar"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			uc:      "matches when all required scopes are present",
			matcher: ExactScopeStrategyMatcher{"foo.bar.baz", "foo.bar"},
			scopes:  []string{"foo.bar.baz", "foo.bar"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc:      "matches when more than all required scopes are present",
			matcher: ExactScopeStrategyMatcher{"foo.bar.baz", "foo.bar"},
			scopes:  []string{"foo.bar.baz", "foo.bar", "baz.baz"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc:      "doesn't match when no required scopes are present",
			matcher: ExactScopeStrategyMatcher{"foo.bar.baz", "foo.bar"},
			scopes:  []string{},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			uc:      "doesn't match not included scope",
			matcher: ExactScopeStrategyMatcher{"foo.bar.baz", "foo.bar"},
			scopes:  []string{"baz.baz"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			uc:      "matches if no required scopes are defined",
			matcher: ExactScopeStrategyMatcher{},
			scopes:  []string{"baz.baz"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			err := tc.matcher.Match(tc.scopes)

			// THEN
			tc.assert(t, err)
		})
	}
}
