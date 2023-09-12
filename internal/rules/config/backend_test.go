package config

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpstreamURLFactoryCreateURL(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc       string
		factory  *Backend
		original string
		expected string
	}{
		{
			uc:       "set host and rewrite scheme",
			factory:  &Backend{Host: "bar.foo", URLRewriter: &URLRewriter{Scheme: "https"}},
			original: "http://foo.bar/foo/bar?baz=bar&bar=foo&foo=baz",
			expected: "https://bar.foo/foo/bar?baz=bar&bar=foo&foo=baz",
		},
		{
			uc:       "set host only",
			factory:  &Backend{Host: "bar.foo"},
			original: "http://foo.bar/foo/bar?baz=bar&bar=foo&foo=baz",
			expected: "http://bar.foo/foo/bar?baz=bar&bar=foo&foo=baz",
		},
		{
			uc:       "set host only for url with urlencoded path fragment",
			factory:  &Backend{Host: "bar.foo"},
			original: "http://foo.bar/foo/%5Bid%5D?baz=bar&bar=foo&foo=baz",
			expected: "http://bar.foo/foo/%5Bid%5D?baz=bar&bar=foo&foo=baz",
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			requestURL, err := url.Parse(tc.original)
			require.NoError(t, err)

			// WHEN
			result := tc.factory.CreateURL(requestURL)

			// THEN
			assert.Equal(t, tc.expected, result.String())
		})
	}
}

func TestUpstreamURLFactoryDeepCopyInto(t *testing.T) {
	t.Parallel()

	// GIVEN
	var out Backend

	in := Backend{
		Host: "bar.foo",
		URLRewriter: &URLRewriter{
			Scheme:              "https",
			PathPrefixToCut:     "/foo",
			PathPrefixToAdd:     "/baz",
			QueryParamsToRemove: QueryParamsRemover{"foo", "bar"},
		},
	}

	// WHEN
	in.DeepCopyInto(&out)

	// THEN
	require.Equal(t, in, out)
}
