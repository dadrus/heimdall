// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
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
	"strings"
	"testing"
)

// Accept legal escaped paths as supplied, preserving exact %XX spellings.
// Arbitrary malformed fuzz input becomes a literal path via net/url, so the
// rewrite is tested against valid URL values instead of undefined RawPath.
func referenceEscapedFragment(value string) string {
	decoded, err := url.PathUnescape(value)
	if err == nil && (&url.URL{Path: decoded, RawPath: value}).EscapedPath() == value {
		return value
	}

	return (&url.URL{Path: value}).EscapedPath()
}

func referenceQueryWithoutKey(raw, key string, remove bool) string {
	if !remove || raw == "" {
		return raw
	}

	parsed, err := url.ParseQuery(raw)
	if err != nil {
		// Invalid query strings are not silently rewritten by Heimdall.
		return raw
	}

	parsed.Del(key)

	return parsed.Encode()
}

// Always choose a complete escaped segment boundary, or the whole path,
// to exercise actual prefix removal even when fuzzed cut values don't match.
func referenceMatchingPrefix(escaped string) string {
	if strings.HasPrefix(escaped, "/") {
		if next := strings.IndexByte(escaped[1:], '/'); next >= 0 {
			return escaped[:next+1]
		}
	}

	return escaped
}

func FuzzURLRewriter(f *testing.F) {
	for _, tc := range [][5]string{
		{"/api/users", "/api", "/v2", "a=1&b=2", "b"},
		{"/files/a%2Fb", "/files", "/archive", "url=http%3A%2F%2Fx&x=1", "x"},
		{"/api/%61dmin", "/api", "/root%2Fv2", "x=1&x=2&z=%2F", "x"},
		{"/%2e%2E/secret", "/%2e%2E", "/safe", "a=1", "missing"},
		{"/prefix/a%2Fb/../c", "/prefix", "/v1", "key=a+b&key=c", "key"},
		{"/p/%ZZ/%", "/p", "/new", "not%ZZ=1", "not"},
		{"/p?q#fragment", "/p", "/x", "x=1;y=2", "x"},
		{"/", "/", "/%23", "?a=%23&b=%252F", "a"},
		{"*", "0", "0", "", ""}, // net/url's special request-target '*'
		{"", "", "", "", ""},
		{"\x00%00\xff", "\x00", "/new", "\xff=1", "\xff"},
	} {
		f.Add(tc[0], tc[1], tc[2], tc[3], tc[4])
	}

	f.Fuzz(func(t *testing.T, pathInput, cutInput, addInput, query, removedKey string) {
		if len(pathInput)+len(cutInput)+len(addInput)+len(query)+len(removedKey) > 8192 {
			return
		}

		escapedPath := referenceEscapedFragment(pathInput)
		decodedPath, err := url.PathUnescape(escapedPath)
		if err != nil {
			t.Fatalf("reference produced invalid escaped path %q: %v", escapedPath, err)
		}

		cut, add := referenceEscapedFragment(cutInput), referenceEscapedFragment(addInput)

		// Exercise both presence/absence of RawPath and a matching/non-matching
		// prefix, as well as rewritten/preserved schemes and queries.
		for _, withRawPath := range []bool{false, true} {
			for _, useMatchingPrefix := range []bool{false, true} {
				before := &url.URL{
					Scheme:   "http",
					Host:     "upstream.example",
					Path:     decodedPath,
					RawQuery: query,
					Fragment: "anchor",
				}
				if withRawPath {
					before.RawPath = escapedPath
				}

				originalEscaped := before.EscapedPath()

				actualCut := cut
				if useMatchingPrefix {
					actualCut = referenceMatchingPrefix(originalEscaped)
				}

				switchScheme := useMatchingPrefix
				removeQueryKey := withRawPath

				rewriter := &URLRewriter{
					PathPrefixToCut: PrefixCutter(actualCut),
					PathPrefixToAdd: PrefixAdder(add),
				}

				if switchScheme {
					rewriter.Scheme = "https"
				}

				if removeQueryKey {
					rewriter.QueryParamsToRemove = QueryParamsRemover{removedKey}
				}

				wantEscaped := add + strings.TrimPrefix(originalEscaped, actualCut)

				wantPath, err := url.PathUnescape(wantEscaped)
				if err != nil {
					t.Fatalf("reference rewrite produced invalid path %q: %v", wantEscaped, err)
				}

				wantQuery := referenceQueryWithoutKey(query, removedKey, removeQueryKey)
				// net/url may re-escape literal characters after a rewrite,
				// notably the special request-target "*" when prefixed.
				// Verify the resulting URL representation, not a raw string
				// that net/url is allowed to canonicalize.
				wantRawPath := ""
				if before.RawPath != "" || wantPath != wantEscaped {
					wantRawPath = wantEscaped
				}

				wantSerializedPath := (&url.URL{Path: wantPath, RawPath: wantRawPath}).EscapedPath()

				rewriter.Rewrite(before)

				if got := before.EscapedPath(); got != wantSerializedPath {
					t.Fatalf("escaped path: input=%q cut=%q add=%q raw=%t: got %q, want %q",
						pathInput, actualCut, add, withRawPath, got, wantSerializedPath)
				}

				if before.Path != wantPath || before.RawQuery != wantQuery ||
					before.Host != "upstream.example" || before.Fragment != "anchor" {
					t.Fatalf("rewrite fields: input=%q raw=%t: path=%q (want %q), query=%q (want %q), host=%q, fragment=%q",
						pathInput, withRawPath, before.Path, wantPath, before.RawQuery, wantQuery, before.Host, before.Fragment)
				}

				wantScheme := "http"
				if switchScheme {
					wantScheme = "https"
				}

				if before.Scheme != wantScheme {
					t.Fatalf("scheme: got %q, want %q", before.Scheme, wantScheme)
				}

				if decoded, err := url.PathUnescape(before.EscapedPath()); err != nil || decoded != before.Path {
					t.Fatalf("inconsistent Path/RawPath: %#v, unescape=%q, err=%v", before, decoded, err)
				}
			}
		}
	})
}

func TestReferenceURLRewriterOracles(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"/files/a%2fb", "/files/a%2fb"},
		{"/api/%ZZ", "/api/%25ZZ"},
		{"/a b", "/a%20b"},
	} {
		if got := referenceEscapedFragment(tc.input); got != tc.want {
			t.Fatalf("escaped oracle %q: got %q, want %q", tc.input, got, tc.want)
		}
	}

	if got := referenceQueryWithoutKey("b=2&a=1&b=3", "b", true); got != "a=1" {
		t.Fatalf("query oracle: got %q, want a=1", got)
	}

	if got := referenceQueryWithoutKey("x=1;y=2", "x", true); got != "x=1;y=2" {
		t.Fatalf("invalid query must remain unchanged, got %q", got)
	}
}
