package config

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrefixAdderAddTo(t *testing.T) {
	t.Parallel()

	// GIVEN
	adder := PrefixAdder("/foo")

	// WHEN
	result := adder.AddTo("/bar")

	// THEN
	assert.Equal(t, "/foo/bar", result)
}

func TestPrefixCutterCurFrom(t *testing.T) {
	t.Parallel()

	// GIVEN
	adder := PrefixCutter("/foo")

	// WHEN
	result := adder.CutFrom("/foo/bar")

	// THEN
	assert.Equal(t, "/bar", result)
}

func TestQueryParamsRemoverRemoveFrom(t *testing.T) {
	t.Parallel()

	// GIVEN
	remover := QueryParamsRemover{"foo", "bar"}

	// WHEN
	result := remover.RemoveFrom("baz=bar&bar=foo&foo=baz")

	// THEN
	assert.Equal(t, "baz=bar", result)
}

func TestURLRewriterRewrite(t *testing.T) {
	for _, tc := range []struct {
		uc       string
		original string
		rewriter *URLRewriter
		expected string
	}{
		{
			uc:       "rewrite scheme only",
			original: "http://foo.bar/foo/bar?baz=bar&bar=foo&foo=baz",
			rewriter: &URLRewriter{Scheme: "https"},
			expected: "https://foo.bar/foo/bar?baz=bar&bar=foo&foo=baz",
		},
		{
			uc:       "rewrite with url encoded path fragments",
			original: "http://foo.bar/%5Bid%5D/bar?baz=bar&bar=foo&foo=baz",
			rewriter: &URLRewriter{},
			expected: "http://foo.bar/%5Bid%5D/bar?baz=bar&bar=foo&foo=baz",
		},
		{
			uc:       "cut only the path prefix",
			original: "http://foo.bar/foo/bar?baz=bar&bar=foo&foo=baz",
			rewriter: &URLRewriter{PathPrefixToCut: "/foo"},
			expected: "http://foo.bar/bar?baz=bar&bar=foo&foo=baz",
		},
		{
			uc:       "cut only the urlencoded path prefix",
			original: "http://foo.bar/%5Bid%5D/bar?baz=bar&bar=foo&foo=baz",
			rewriter: &URLRewriter{PathPrefixToCut: "/[id]"},
			expected: "http://foo.bar/bar?baz=bar&bar=foo&foo=baz",
		},
		{
			uc:       "add only a path prefix",
			original: "http://foo.bar/foo/bar?baz=bar&bar=foo&foo=baz",
			rewriter: &URLRewriter{PathPrefixToAdd: "/baz"},
			expected: "http://foo.bar/baz/foo/bar?baz=bar&bar=foo&foo=baz",
		},
		{
			uc:       "remove only a query param",
			original: "http://foo.bar/foo/bar?baz=bar&bar=foo&foo=baz",
			rewriter: &URLRewriter{QueryParamsToRemove: QueryParamsRemover{"baz"}},
			expected: "http://foo.bar/foo/bar?bar=foo&foo=baz",
		},
		{
			uc:       "rewrite everything",
			original: "http://foo.bar/foo/bar?baz=bar&bar=foo&foo=baz",
			rewriter: &URLRewriter{
				Scheme:              "https",
				PathPrefixToCut:     "/foo",
				PathPrefixToAdd:     "/baz",
				QueryParamsToRemove: QueryParamsRemover{"foo", "bar"},
			},
			expected: "https://foo.bar/baz/bar?baz=bar",
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			requestURL, err := url.Parse(tc.original)
			require.NoError(t, err)

			// WHEN
			tc.rewriter.Rewrite(requestURL)

			// THEN
			assert.Equal(t, tc.expected, requestURL.String())
		})
	}
}
