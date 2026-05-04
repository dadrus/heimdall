package secrets

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInternalRef(t *testing.T) {
	t.Parallel()

	ref := InternalRef("foo", "bar")

	assert.Equal(t, "foo", ref.Source)
	assert.Equal(t, "bar", ref.Selector)
	assert.Empty(t, ref.Namespace)
	assert.False(t, ref.RuleContext)
}

func TestRuleRef(t *testing.T) {
	t.Parallel()

	ref := RuleRef("foo", "bar", "baz")

	assert.Equal(t, "foo", ref.Source)
	assert.Equal(t, "bar", ref.Selector)
	assert.Equal(t, "baz", ref.Namespace)
	assert.True(t, ref.RuleContext)
}

func TestReferenceParent(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		reference Reference
		expected  Reference
	}{
		"removes last selector segment": {
			reference: Reference{
				Source:      "vault",
				Selector:    "jwt/signing/2026-05",
				Namespace:   "tenant-a",
				RuleContext: true,
			},
			expected: Reference{
				Source:      "vault",
				Selector:    "jwt/signing",
				Namespace:   "tenant-a",
				RuleContext: true,
			},
		},
		"single segment selector resolves to root": {
			reference: Reference{
				Source:      "pem",
				Selector:    "server",
				Namespace:   "tenant-a",
				RuleContext: true,
			},
			expected: Reference{
				Source:      "pem",
				Selector:    "",
				Namespace:   "tenant-a",
				RuleContext: true,
			},
		},
		"empty selector remains root": {
			reference: Reference{
				Source:    "pem",
				Selector:  "",
				Namespace: "tenant-a",
			},
			expected: Reference{
				Source:    "pem",
				Selector:  "",
				Namespace: "tenant-a",
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.expected, tc.reference.Parent())
		})
	}
}
