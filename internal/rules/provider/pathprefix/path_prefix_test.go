package pathprefix

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
)

func TestPathPrefixVerify(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		prefix PathPrefix
		url    string
		fail   bool
	}{
		{uc: "path only and without required prefix", prefix: "/foo/bar", url: "/bar/foo/moo", fail: true},
		{uc: "path only with required prefix", prefix: "/foo/bar", url: "/foo/bar/moo", fail: false},
		{uc: "full url and without required prefix", prefix: "/foo/bar", url: "https://<**>/bar/foo/moo", fail: true},
		{uc: "full url with required prefix", prefix: "/foo/bar", url: "https://<**>/foo/bar/moo", fail: false},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// WHEN
			err := tc.prefix.Verify([]config.RuleConfig{{URL: tc.url}})

			if tc.fail {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
