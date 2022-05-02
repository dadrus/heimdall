package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHierarchicScopeStrategy(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc             string
		requiredScopes HierarchicScopeStrategyMatcher
		providedScopes []string
		assert         func(t *testing.T, err error)
	}{
		{
			uc:             "empty required scopes match single provided scope",
			requiredScopes: HierarchicScopeStrategyMatcher{},
			providedScopes: []string{"foo.bar"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc:             "empty required scopes match multiple provided scopes",
			requiredScopes: HierarchicScopeStrategyMatcher{},
			providedScopes: []string{"foo.bar", "bar.foo"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc:             "empty required scopes do match empty provided scopes",
			requiredScopes: HierarchicScopeStrategyMatcher{},
			providedScopes: []string{"foo.bar", "bar.foo"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc:             "required scopes with single element match provided scopes with exact same single scope",
			requiredScopes: HierarchicScopeStrategyMatcher{"foo.bar"},
			providedScopes: []string{"foo.bar"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc:             "required scopes with single element matches provided scopes with a single scope on root level",
			requiredScopes: HierarchicScopeStrategyMatcher{"foo.bar"},
			providedScopes: []string{"foo"}, // foo includes foo.bar, foo.baz, foo.*, etc
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			// nolint: lll
			uc:             "required scopes with single element doesn't match provided scopes with a single scope having required scope as prefix",
			requiredScopes: HierarchicScopeStrategyMatcher{"foo.bar"},
			providedScopes: []string{"foo.bar.baz"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			uc:             "required scopes with single element doesn't match empty provided scopes",
			requiredScopes: HierarchicScopeStrategyMatcher{"foo.bar"},
			providedScopes: []string{},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			// nolint: lll
			uc:             "required scopes with multiple elements match provided scopes in hierarchy, which also include further scopes",
			requiredScopes: HierarchicScopeStrategyMatcher{"foo.bar", "bar.foo"},
			providedScopes: []string{"foo", "bar.foo", "baz"},
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
