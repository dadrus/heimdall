package oauth2

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWildcardScopeStrategy(t *testing.T) {
	t.Parallel()

	strategy := WildcardScopeStrategyMatcher{}
	scopes := []string{}

	assert.False(t, strategy.Match(scopes, "foo.bar.baz"))
	assert.False(t, strategy.Match(scopes, "foo.bar"))

	scopes = []string{"*"}
	assert.False(t, strategy.Match(scopes, ""))
	assert.True(t, strategy.Match(scopes, "asdf"))
	assert.True(t, strategy.Match(scopes, "asdf.asdf"))

	scopes = []string{"foo"}
	assert.False(t, strategy.Match(scopes, "*"))
	assert.False(t, strategy.Match(scopes, "foo.*"))
	assert.False(t, strategy.Match(scopes, "fo*"))
	assert.True(t, strategy.Match(scopes, "foo"))

	scopes = []string{"foo*"}
	assert.False(t, strategy.Match(scopes, "foo"))
	assert.False(t, strategy.Match(scopes, "fooa"))
	assert.False(t, strategy.Match(scopes, "fo"))
	assert.True(t, strategy.Match(scopes, "foo*"))

	scopes = []string{"foo.*"}
	assert.True(t, strategy.Match(scopes, "foo.bar"))
	assert.True(t, strategy.Match(scopes, "foo.baz"))
	assert.True(t, strategy.Match(scopes, "foo.bar.baz"))
	assert.False(t, strategy.Match(scopes, "foo"))

	scopes = []string{"foo.*.baz"}
	assert.True(t, strategy.Match(scopes, "foo.*.baz"))
	assert.True(t, strategy.Match(scopes, "foo.bar.baz"))
	assert.False(t, strategy.Match(scopes, "foo..baz"))
	assert.False(t, strategy.Match(scopes, "foo.baz"))
	assert.False(t, strategy.Match(scopes, "foo"))
	assert.False(t, strategy.Match(scopes, "foo.bar.bar"))

	scopes = []string{"foo.*.bar.*"}
	assert.True(t, strategy.Match(scopes, "foo.baz.bar.baz"))
	assert.False(t, strategy.Match(scopes, "foo.baz.baz.bar.baz"))
	assert.True(t, strategy.Match(scopes, "foo.baz.bar.bar.bar"))
	assert.False(t, strategy.Match(scopes, "foo.baz.bar"))
	assert.True(t, strategy.Match(scopes, "foo.*.bar.*.*.*"))
	assert.True(t, strategy.Match(scopes, "foo.1.bar.1.2.3.4.5"))

	scopes = []string{"foo.*.bar"}
	assert.True(t, strategy.Match(scopes, "foo.bar.bar"))
	assert.False(t, strategy.Match(scopes, "foo.bar.bar.bar"))
	assert.False(t, strategy.Match(scopes, "foo..bar"))
	assert.False(t, strategy.Match(scopes, "foo.bar..bar"))

	scopes = []string{"foo.*.bar.*.baz.*"}
	assert.False(t, strategy.Match(scopes, "foo.*.*"))
	assert.False(t, strategy.Match(scopes, "foo.*.bar"))
	assert.False(t, strategy.Match(scopes, "foo.baz.*"))
	assert.False(t, strategy.Match(scopes, "foo.baz.bar"))
	assert.False(t, strategy.Match(scopes, "foo.b*.bar"))
	assert.True(t, strategy.Match(scopes, "foo.bar.bar.baz.baz.baz"))
	assert.True(t, strategy.Match(scopes, "foo.bar.bar.baz.baz.baz.baz"))
	assert.False(t, strategy.Match(scopes, "foo.bar.bar.baz.baz"))
	assert.False(t, strategy.Match(scopes, "foo.bar.baz.baz.baz.bar"))

	scopes = strings.Fields("hydra.* openid offline  hydra")
	assert.True(t, strategy.Match(scopes, "hydra.clients"))
	assert.True(t, strategy.Match(scopes, "hydra.clients.get"))
	assert.True(t, strategy.Match(scopes, "hydra"))
	assert.True(t, strategy.Match(scopes, "offline"))
	assert.True(t, strategy.Match(scopes, "openid"))
}
