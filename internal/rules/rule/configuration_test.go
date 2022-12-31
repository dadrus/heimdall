package rule

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
)

func TestRuleConfigDeepCopyInto(t *testing.T) {
	t.Parallel()

	// GIVEN
	var out Configuration

	in := Configuration{
		ID: "foo",
		RuleMatcher: Matcher{
			URL:      "bar",
			Strategy: "glob",
		},
		Upstream:     "baz",
		Methods:      []string{"GET", "PATCH"},
		Execute:      []config.MechanismConfig{{"foo": "bar"}},
		ErrorHandler: []config.MechanismConfig{{"bar": "foo"}},
	}

	// WHEN
	in.DeepCopyInto(&out)

	// THEN
	assert.Equal(t, in.ID, out.ID)
	assert.Equal(t, in.RuleMatcher.URL, out.RuleMatcher.URL)
	assert.Equal(t, in.Upstream, out.Upstream)
	assert.Equal(t, in.RuleMatcher.Strategy, out.RuleMatcher.Strategy)
	assert.Equal(t, in.Methods, out.Methods)
	assert.Equal(t, in.Execute, out.Execute)
	assert.Equal(t, in.ErrorHandler, out.ErrorHandler)
}

func TestRuleConfigDeepCopy(t *testing.T) {
	t.Parallel()

	// GIVEN
	in := Configuration{
		ID: "foo",
		RuleMatcher: Matcher{
			URL:      "bar",
			Strategy: "glob",
		},
		Upstream:     "baz",
		Methods:      []string{"GET", "PATCH"},
		Execute:      []config.MechanismConfig{{"foo": "bar"}},
		ErrorHandler: []config.MechanismConfig{{"bar": "foo"}},
	}

	// WHEN
	out := in.DeepCopy()

	// THEN
	// different addresses
	require.False(t, &in == out)

	// but same contents
	assert.Equal(t, in.ID, out.ID)
	assert.Equal(t, in.RuleMatcher.URL, out.RuleMatcher.URL)
	assert.Equal(t, in.Upstream, out.Upstream)
	assert.Equal(t, in.RuleMatcher.Strategy, out.RuleMatcher.Strategy)
	assert.Equal(t, in.Methods, out.Methods)
	assert.Equal(t, in.Execute, out.Execute)
	assert.Equal(t, in.ErrorHandler, out.ErrorHandler)
}
