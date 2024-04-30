package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
)

func TestMatcherConstraintsToRequestMatcher(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc            string
		constraints   *MatcherConstraints
		slashHandling EncodedSlashesHandling
		assert        func(t *testing.T, matcher RequestMatcher, err error)
	}{
		{
			uc: "no constraints",
			assert: func(t *testing.T, matcher RequestMatcher, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Empty(t, matcher)
			},
		},
		{
			uc:          "host matcher creation fails",
			constraints: &MatcherConstraints{HostRegex: "?>?<*??"},
			assert: func(t *testing.T, _ RequestMatcher, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "filed to compile host expression")
			},
		},
		{
			uc:          "path matcher creation fails",
			constraints: &MatcherConstraints{PathRegex: "?>?<*??"},
			assert: func(t *testing.T, _ RequestMatcher, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "filed to compile path expression")
			},
		},
		{
			uc:          "method matcher creation fails",
			constraints: &MatcherConstraints{Methods: []string{""}},
			assert: func(t *testing.T, _ RequestMatcher, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "methods list contains empty values")
			},
		},
		{
			uc: "with all matchers",
			constraints: &MatcherConstraints{
				Methods:   []string{"GET"},
				Scheme:    "https",
				HostRegex: "^example.com",
				PathGlob:  "/foo/bar/*",
			},
			assert: func(t *testing.T, matcher RequestMatcher, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Len(t, matcher, 4)

				assert.Contains(t, matcher, schemeMatcher("https"))
				assert.Contains(t, matcher, methodMatcher{"GET"})
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			matcher, err := tc.constraints.ToRequestMatcher(tc.slashHandling)

			tc.assert(t, matcher, err)
		})
	}
}
