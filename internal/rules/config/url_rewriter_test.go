// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

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
	for uc, tc := range map[string]struct {
		original string
		rewriter *URLRewriter
		expected string
	}{
		"rewrite scheme only": {
			original: "http://foo.bar/foo/bar?baz=bar&bar=foo&foo=baz",
			rewriter: &URLRewriter{Scheme: "https"},
			expected: "https://foo.bar/foo/bar?baz=bar&bar=foo&foo=baz",
		},
		"rewrite with url encoded path fragments": {
			original: "http://foo.bar/%5Bid%5D/bar?baz=bar&bar=foo&foo=baz",
			rewriter: &URLRewriter{},
			expected: "http://foo.bar/%5Bid%5D/bar?baz=bar&bar=foo&foo=baz",
		},
		"cut only the path prefix": {
			original: "http://foo.bar/foo/bar?baz=bar&bar=foo&foo=baz",
			rewriter: &URLRewriter{PathPrefixToCut: "/foo"},
			expected: "http://foo.bar/bar?baz=bar&bar=foo&foo=baz",
		},
		"cut only the urlencoded path prefix": {
			original: "http://foo.bar/%5Bid%5D/bar?baz=bar&bar=foo&foo=baz",
			rewriter: &URLRewriter{PathPrefixToCut: "/%5Bid%5D"},
			expected: "http://foo.bar/bar?baz=bar&bar=foo&foo=baz",
		},
		"cut only the urlencoded path prefix with encoded slash": {
			original: "http://foo.bar/foo%2Ftest/%5Bid%5D/bar?baz=bar&bar=foo&foo=baz",
			rewriter: &URLRewriter{PathPrefixToCut: "/foo%2Ftest"},
			expected: "http://foo.bar/%5Bid%5D/bar?baz=bar&bar=foo&foo=baz",
		},
		"add only a path prefix": {
			original: "http://foo.bar/foo/bar?baz=bar&bar=foo&foo=baz",
			rewriter: &URLRewriter{PathPrefixToAdd: "/baz"},
			expected: "http://foo.bar/baz/foo/bar?baz=bar&bar=foo&foo=baz",
		},
		"add a path prefix with urlencoded slash": {
			original: "http://foo.bar/foo/bar?baz=bar&bar=foo&foo=baz",
			rewriter: &URLRewriter{PathPrefixToAdd: "/foo%2Ftest"},
			expected: "http://foo.bar/foo%2Ftest/foo/bar?baz=bar&bar=foo&foo=baz",
		},
		"remove only a query param": {
			original: "http://foo.bar/foo/bar?baz=bar&bar=foo&foo=baz",
			rewriter: &URLRewriter{QueryParamsToRemove: QueryParamsRemover{"baz"}},
			expected: "http://foo.bar/foo/bar?bar=foo&foo=baz",
		},
		"rewrite everything": {
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
		t.Run(uc, func(t *testing.T) {
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

func TestURLRewriterDeepCopyInto(t *testing.T) {
	t.Parallel()

	// GIVEN
	in := &URLRewriter{
		Scheme:              "https",
		PathPrefixToCut:     "/foo",
		PathPrefixToAdd:     "/baz",
		QueryParamsToRemove: QueryParamsRemover{"foo", "bar", "baz"},
	}

	var out URLRewriter

	// WHEN
	in.DeepCopyInto(&out)

	// THEN
	assert.Equal(t, in, &out)

	in.QueryParamsToRemove[0] = "oof"
	assert.NotElementsMatch(t, in.QueryParamsToRemove, out.QueryParamsToRemove)
}
