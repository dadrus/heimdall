package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRuleSetConfigurationVerifyPathPrefixPathPrefixVerify(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		prefix string
		url    string
		fail   bool
	}{
		{uc: "path only and without required prefix", prefix: "/foo/bar", url: "/bar/foo/moo", fail: true},
		{uc: "path only with required prefix", prefix: "/foo/bar", url: "/foo/bar/moo", fail: false},
		{uc: "full url and without required prefix", prefix: "/foo/bar", url: "https://<**>/bar/foo/moo", fail: true},
		{uc: "full url with required prefix", prefix: "/foo/bar", url: "https://<**>/foo/bar/moo", fail: false},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			rs := RuleSet{
				Rules: []Rule{{RuleMatcher: Matcher{URL: tc.url}}},
			}

			// WHEN
			err := rs.VerifyPathPrefix(tc.prefix)

			if tc.fail {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
