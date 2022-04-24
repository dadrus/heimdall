package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHierarchicScopeStrategy(t *testing.T) {
	t.Parallel()

	strategy := HierarchicScopeStrategyMatcher{}
	scopes := []string{}

	assert.False(t, strategy.Match(scopes, "foo.bar.baz"))
	assert.False(t, strategy.Match(scopes, "foo.bar"))
	assert.False(t, strategy.Match(scopes, "foo"))

	scopes = []string{"foo.bar", "bar.baz", "baz.baz.1", "baz.baz.2", "baz.baz.3", "baz.baz.baz"}
	assert.True(t, strategy.Match(scopes, "foo.bar.baz"))
	assert.True(t, strategy.Match(scopes, "baz.baz.baz"))
	assert.True(t, strategy.Match(scopes, "foo.bar"))
	assert.False(t, strategy.Match(scopes, "foo"))

	assert.True(t, strategy.Match(scopes, "bar.baz"))
	assert.True(t, strategy.Match(scopes, "bar.baz.zad"))
	assert.False(t, strategy.Match(scopes, "bar"))
	assert.False(t, strategy.Match(scopes, "baz"))

	scopes = []string{"fosite.keys.create", "fosite.keys.get", "fosite.keys.delete", "fosite.keys.update"}
	assert.True(t, strategy.Match(scopes, "fosite.keys.delete"))
	assert.True(t, strategy.Match(scopes, "fosite.keys.get"))
	assert.True(t, strategy.Match(scopes, "fosite.keys.get"))
	assert.True(t, strategy.Match(scopes, "fosite.keys.update"))

	scopes = []string{"hydra", "openid", "offline"}
	assert.False(t, strategy.Match(scopes, "foo.bar"))
	assert.False(t, strategy.Match(scopes, "foo"))
	assert.True(t, strategy.Match(scopes, "hydra"))
	assert.True(t, strategy.Match(scopes, "hydra.bar"))
	assert.True(t, strategy.Match(scopes, "openid"))
	assert.True(t, strategy.Match(scopes, "openid.baz.bar"))
	assert.True(t, strategy.Match(scopes, "offline"))
	assert.True(t, strategy.Match(scopes, "offline.baz.bar.baz"))
}
