package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMatcherDeepCopyInto(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		in     *Matcher
		assert func(t *testing.T, out *Matcher)
	}{
		{
			uc: "with path only",
			in: &Matcher{Path: "/foo/bar"},
			assert: func(t *testing.T, out *Matcher) {
				t.Helper()

				assert.Equal(t, "/foo/bar", out.Path)
				assert.Nil(t, out.With)
			},
		},
		{
			uc: "with path and simple constraints",
			in: &Matcher{Path: "/foo/bar", With: &MatcherConstraints{Scheme: "http"}},
			assert: func(t *testing.T, out *Matcher) {
				t.Helper()

				assert.Equal(t, "/foo/bar", out.Path)
				require.NotNil(t, out.With)
				assert.Equal(t, "http", out.With.Scheme)
			},
		},
		{
			uc: "with path and complex constraints",
			in: &Matcher{Path: "/foo/bar", With: &MatcherConstraints{Methods: []string{"GET"}, Scheme: "http"}},
			assert: func(t *testing.T, out *Matcher) {
				t.Helper()

				assert.Equal(t, "/foo/bar", out.Path)
				require.NotNil(t, out.With)
				assert.Equal(t, "http", out.With.Scheme)
				assert.ElementsMatch(t, out.With.Methods, []string{"GET"})
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			out := new(Matcher)

			tc.in.DeepCopyInto(out)

			tc.assert(t, out)
		})
	}
}
