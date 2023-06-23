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
		factory  *UpstreamURLFactory
		expected string
	}{
		{
			uc:       "set host and rewrite scheme",
			factory:  &UpstreamURLFactory{Host: "bar.foo", URLRewriter: &URLRewriter{Scheme: "https"}},
			expected: "https://bar.foo/foo/bar?baz=bar&bar=foo&foo=baz",
		},
		{
			uc:       "set host only",
			factory:  &UpstreamURLFactory{Host: "bar.foo"},
			expected: "http://bar.foo/foo/bar?baz=bar&bar=foo&foo=baz",
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			requestURL := &url.URL{
				Scheme:   "http",
				Host:     "foo.bar",
				Path:     "/foo/bar",
				RawQuery: "baz=bar&bar=foo&foo=baz",
			}

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
	var out UpstreamURLFactory

	in := UpstreamURLFactory{
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
