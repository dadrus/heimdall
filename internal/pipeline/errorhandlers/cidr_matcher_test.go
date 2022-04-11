package errorhandlers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateNewCIDRMatcherUsingProperCIDRValues(t *testing.T) {
	// GIVEN
	cidrs := []string{
		"192.168.1.0/24",
		"10.10.0.0/16",
	}

	// WHEN
	matcher, err := NewCIDRMatcher(cidrs)

	// THEN
	require.NoError(t, err)
	assert.NotNil(t, matcher)
}

func TestCreateNewCIDRMatcherUsingBadCIDRValues(t *testing.T) {
	// GIVEN
	cidrs := []string{
		"192.168.1.0/foo",
		"10.10.0.0/16",
	}

	// WHEN
	matcher, err := NewCIDRMatcher(cidrs)

	// THEN
	require.Error(t, err)
	assert.Nil(t, matcher)
}

func TestCIDRMatcherMatchIPsInTheRange(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc       string
		cidrs    []string
		ips      []string
		matching bool
	}{
		{
			uc:       "match ips in the range",
			cidrs:    []string{"192.168.1.0/24", "10.10.0.0/16"},
			ips:      []string{"192.168.1.10", "10.10.20.124"},
			matching: true,
		},
		{
			uc:       "don't match ips out of range",
			cidrs:    []string{"192.168.1.0/24", "10.10.0.0/16"},
			ips:      []string{"192.168.2.10", "10.11.20.124"},
			matching: false,
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			matcher, err := NewCIDRMatcher(tc.cidrs)
			require.NoError(t, err)

			// WHEN
			matched := matcher.Match(tc.ips...)

			// THEN
			assert.Equal(t, tc.matching, matched)
		})
	}
}
