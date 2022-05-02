package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWildcardScopeStrategy(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc             string
		requiredScopes WildcardScopeStrategyMatcher
		providedScopes []string
		assert         func(t *testing.T, err error)
	}{
		{
			uc:             "empty required scopes match empty provides scopes",
			requiredScopes: WildcardScopeStrategyMatcher{},
			providedScopes: []string{},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc:             "empty string required scope doesn't match wildcard",
			requiredScopes: WildcardScopeStrategyMatcher{""},
			providedScopes: []string{"*"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			uc:             "empty string required scope doesn't match provided specific clam",
			requiredScopes: WildcardScopeStrategyMatcher{""},
			providedScopes: []string{"foo"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			uc:             "wildcard required scope matches wildcard provided scope",
			requiredScopes: WildcardScopeStrategyMatcher{"*"},
			providedScopes: []string{"*"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc:             "wildcard required scope doesn't match specific provided scope",
			requiredScopes: WildcardScopeStrategyMatcher{"*"},
			providedScopes: []string{"foo"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			uc:             "wildcard required scope doesn't match specific hierarchic provided scope",
			requiredScopes: WildcardScopeStrategyMatcher{"*"},
			providedScopes: []string{"foo.bar"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			uc:             "wildcard required scope doesn't match specific hierarchic wildcard scope",
			requiredScopes: WildcardScopeStrategyMatcher{"*"},
			providedScopes: []string{"foo.*.bar"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			uc:             "simple required scope matches wildcard as provided scope",
			requiredScopes: WildcardScopeStrategyMatcher{"foo"},
			providedScopes: []string{"*"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc:             "simple required scope doesn't matches prefixed wildcard scope as provided scope",
			requiredScopes: WildcardScopeStrategyMatcher{"foo"},
			providedScopes: []string{"foo*"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			uc:             "simple required scope doesn't matches hierarchical wildcard scope as provided scope",
			requiredScopes: WildcardScopeStrategyMatcher{"foo"},
			providedScopes: []string{"foo.*"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			uc:             "single simple hierarchical required scope matches wildcard provided scope",
			requiredScopes: WildcardScopeStrategyMatcher{"foo.bar"},
			providedScopes: []string{"*"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc:             "single simple required scope does not match empty provided scopes",
			requiredScopes: WildcardScopeStrategyMatcher{"foo.bar"},
			providedScopes: []string{},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			uc:             "single simple hierarchical required scope matches root dor-prefixed wildcard provided scopes",
			requiredScopes: WildcardScopeStrategyMatcher{"foo.bar"},
			providedScopes: []string{"foo.*"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc:             "single simple hierarchical required scope doesn't match root prefixed wildcard provided scopes",
			requiredScopes: WildcardScopeStrategyMatcher{"foo.bar"},
			providedScopes: []string{"foo*"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			uc:             "single simple hierarchical required scope doesn't match partially root prefixed wildcard provided scopes",
			requiredScopes: WildcardScopeStrategyMatcher{"foo.bar"},
			providedScopes: []string{"fo*"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			uc:             "hierarchical wildcard required scope matches wildcard provided scope",
			requiredScopes: WildcardScopeStrategyMatcher{"foo.*.bar"},
			providedScopes: []string{"*"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc:             "hierarchical wildcard required scope matches root prefixed partial wildcard provided scope",
			requiredScopes: WildcardScopeStrategyMatcher{"foo.*.bar"},
			providedScopes: []string{"foo.*"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc:             "hierarchical wildcard required scope doesn't match hierarchical provided scope with not matching parts",
			requiredScopes: WildcardScopeStrategyMatcher{"foo.*.bar"},
			providedScopes: []string{"foo.baz.bar"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			uc:             "partially wildcard required scope matches wildcard provided scope",
			requiredScopes: WildcardScopeStrategyMatcher{"fo*"},
			providedScopes: []string{"*"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
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
