package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRuleConfigDeepCopyInto(t *testing.T) {
	t.Parallel()

	// GIVEN
	var out RuleConfig

	in := RuleConfig{
		ID:               "foo",
		URL:              "bar",
		Upstream:         "baz",
		MatchingStrategy: "glob",
		Methods:          []string{"GET", "PATCH"},
		Execute:          []MechanismConfig{{"foo": "bar"}},
		ErrorHandler:     []MechanismConfig{{"bar": "foo"}},
	}

	// WHEN
	in.DeepCopyInto(&out)

	// THEN
	assert.Equal(t, in.ID, out.ID)
	assert.Equal(t, in.URL, out.URL)
	assert.Equal(t, in.Upstream, out.Upstream)
	assert.Equal(t, in.MatchingStrategy, out.MatchingStrategy)
	assert.Equal(t, in.Methods, out.Methods)
	assert.Equal(t, in.Execute, out.Execute)
	assert.Equal(t, in.ErrorHandler, out.ErrorHandler)
}

func TestRuleConfigDeepCopy(t *testing.T) {
	t.Parallel()

	// GIVEN
	in := RuleConfig{
		ID:               "foo",
		URL:              "bar",
		Upstream:         "baz",
		MatchingStrategy: "glob",
		Methods:          []string{"GET", "PATCH"},
		Execute:          []MechanismConfig{{"foo": "bar"}},
		ErrorHandler:     []MechanismConfig{{"bar": "foo"}},
	}

	// WHEN
	out := in.DeepCopy()

	// THEN
	// different addresses
	require.False(t, &in == out)

	// but same contents
	assert.Equal(t, in.ID, out.ID)
	assert.Equal(t, in.URL, out.URL)
	assert.Equal(t, in.Upstream, out.Upstream)
	assert.Equal(t, in.MatchingStrategy, out.MatchingStrategy)
	assert.Equal(t, in.Methods, out.Methods)
	assert.Equal(t, in.Execute, out.Execute)
	assert.Equal(t, in.ErrorHandler, out.ErrorHandler)
}
