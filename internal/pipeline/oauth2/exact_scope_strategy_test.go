package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExactScopeStrategy2ScopeStrategy(t *testing.T) {
	t.Parallel()

	strategy := ExactScopeStrategyMatcher{}

	scopes := []string{"foo.bar.baz", "foo.bar"}
	assert.True(t, strategy.Match(scopes, "foo.bar.baz"))
	assert.True(t, strategy.Match(scopes, "foo.bar"))

	assert.False(t, strategy.Match(scopes, "foo.bar.baz.baz"))
	assert.False(t, strategy.Match(scopes, "foo.bar.bar"))

	assert.False(t, strategy.Match(scopes, "foo.bar.baz1"))
	assert.False(t, strategy.Match(scopes, "foo.bar1"))

	assert.False(t, strategy.Match([]string{}, "foo"))
}
