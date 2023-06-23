package config

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
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
	t.Parallel()

	for _, tc := range []struct {
		uc       string
		rewriter *URLRewriter
		expected string
	}{
		{
			uc:       "rewrite scheme only",
			rewriter: &URLRewriter{Scheme: "https"},
			expected: "https://foo.bar/foo/bar?baz=bar&bar=foo&foo=baz",
		},
		{
			uc:       "cut only the path prefix",
			rewriter: &URLRewriter{PathPrefixToCut: "/foo"},
			expected: "http://foo.bar/bar?baz=bar&bar=foo&foo=baz",
		},
		{
			uc:       "add only a path prefix",
			rewriter: &URLRewriter{PathPrefixToAdd: "/baz"},
			expected: "http://foo.bar/baz/foo/bar?baz=bar&bar=foo&foo=baz",
		},
		{
			uc:       "remove only a query param",
			rewriter: &URLRewriter{QueryParamsToRemove: QueryParamsRemover{"baz"}},
			expected: "http://foo.bar/foo/bar?bar=foo&foo=baz",
		},
		{
			uc: "rewrite everything",
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
			requestURL := &url.URL{
				Scheme:   "http",
				Host:     "foo.bar",
				Path:     "/foo/bar",
				RawQuery: "baz=bar&bar=foo&foo=baz",
			}

			// WHEN
			tc.rewriter.Rewrite(requestURL)

			// THEN
			assert.Equal(t, tc.expected, requestURL.String())
		})
	}
}
