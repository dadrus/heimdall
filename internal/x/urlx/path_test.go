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

package urlx

import (
	"fmt"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPathHasDotSegments(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		path     string
		expected bool
	}{
		"no dot segment": {
			path: "/foo/bar",
		},
		"dot in a path segment": {
			path: "/foo/bar.baz",
		},
		"two dots in a path segment": {
			path: "/foo/bar..baz",
		},
		"only encoded slash in a path": {
			path: "/foo%2fbar",
		},
		"single dot segment": {
			path:     "/foo/./bar",
			expected: true,
		},
		"double dot segment": {
			path:     "/foo/../bar",
			expected: true,
		},
		"multiple dot segment": {
			path:     "/foo/../../bar",
			expected: true,
		},
		"encoded double dot and slash lowercase": {
			path:     "/foo/%2e%2e%2fbar",
			expected: true,
		},
		"encoded double dot and slash lowercase 2": {
			path:     "/foo%2f%2e%2e/bar",
			expected: true,
		},
		"encoded double dot and slash uppercase": {
			path:     "/foo/%2E%2E%2Fbar",
			expected: true,
		},
		"encoded double dot and slash uppercase 2": {
			path:     "/foo%2F%2E%2E/bar",
			expected: true,
		},
		"mixed dot encoding": {
			path:     "/foo/.%2e/bar",
			expected: true,
		},
		"encoded backslash as separator": {
			path:     "/foo/%2e%2e%5cbar",
			expected: true,
		},
		"encoded backslash as separator 2": {
			path:     "/foo%5c%2e%2e/bar",
			expected: true,
		},
		"encoded slash without dot segment": {
			path: "/foo%2Fbar",
		},
	} {
		t.Run(uc, func(t *testing.T) {
			assert.Equal(t, tc.expected, PathHasDotSegments(tc.path))
		})
	}
}

func TestContainsEncodedSlash(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		path     string
		expected bool
	}{
		"empty": {},
		"without escapes": {
			path: "/api/v1/resource",
		},
		"uppercase sequence": {
			path:     "/api%2Fv1/resource",
			expected: true,
		},
		"lowercase sequence": {
			path:     "/api%2fv1/resource",
			expected: true,
		},
		"mixed in long path": {
			path:     "/foo/bar/baz%2Fqux/quux",
			expected: true,
		},
		"not slash escape": {
			path: "/api%2Ev1/resource",
		},
		"incomplete escape": {
			path: "/api%2",
		},
	} {
		t.Run(uc, func(t *testing.T) {
			assert.Equal(t, tc.expected, ContainsEncodedSlash(tc.path))
		})
	}
}

func TestNormalizePath(t *testing.T) {
	t.Parallel()

	for given, expected := range map[string]string{
		"/":                              "/",
		"/.././":                         "/",
		"/../":                           "/",
		"/../../":                        "/",
		"/bar/baz":                       "/bar/baz",
		"/bar/baz/":                      "/bar/baz/",
		"/bar/./baz":                     "/bar/baz",
		"/bar/./baz/":                    "/bar/baz/",
		"/bar//baz":                      "/bar/baz",
		"/bar//baz/":                     "/bar/baz/",
		"/bar/../baz":                    "/baz",
		"/bar/../baz/":                   "/baz/",
		"/bar/../../baz/":                "/baz/",
		"/bar/../test/foo/%5Bval%5D":     "/test/foo/%5Bval%5D",
		"/bar/%2e.%2ftest/foo/%5Bval%5D": "/bar/%2e.%2ftest/foo/%5Bval%5D",
	} {
		t.Run(given, func(t *testing.T) {
			result := NormalizePath(given)

			assert.Equal(t, expected, result)
		})
	}
}

func TestPathUnescape(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		value    string
		opts     UnescapeOptions
		expected string
	}{
		"zero options decode all": {
			value:    "api%2Fv1%5Bid%5D",
			expected: "api/v1[id]",
		},
		"all decodes uppercase slash": {
			value:    "api%2Fv1",
			opts:     UnescapeOptions{Mode: UnescapeAll},
			expected: "api/v1",
		},
		"all decodes lowercase slash": {
			value:    "api%2fv1",
			opts:     UnescapeOptions{Mode: UnescapeAll},
			expected: "api/v1",
		},
		"all decodes non slash escapes": {
			value:    "foo%5Bid%5D",
			opts:     UnescapeOptions{Mode: UnescapeAll},
			expected: "foo[id]",
		},
		"all decodes mixed escapes": {
			value:    "api%2Fv1%5Bid%5D",
			opts:     UnescapeOptions{Mode: UnescapeAll},
			expected: "api/v1[id]",
		},
		"all performs single pass": {
			value:    "%2561",
			opts:     UnescapeOptions{Mode: UnescapeAll},
			expected: "%61",
		},
		"all decodes separately encoded percent sequence once": {
			value:    "%25%36%31",
			opts:     UnescapeOptions{Mode: UnescapeAll},
			expected: "%61",
		},
		"all except slash preserves uppercase slash": {
			value:    "api%2Fv1",
			opts:     UnescapeOptions{Mode: UnescapeAllExceptSlash},
			expected: "api%2Fv1",
		},
		"all except slash preserves lowercase slash": {
			value:    "api%2fv1",
			opts:     UnescapeOptions{Mode: UnescapeAllExceptSlash},
			expected: "api%2fv1",
		},
		"all except slash decodes non slash escapes": {
			value:    "foo%5Bid%5D",
			opts:     UnescapeOptions{Mode: UnescapeAllExceptSlash},
			expected: "foo[id]",
		},
		"all except slash decodes mixed escapes": {
			value:    "api%2Fv1%5Bid%5D",
			opts:     UnescapeOptions{Mode: UnescapeAllExceptSlash},
			expected: "api%2Fv1[id]",
		},
		"all except slash decodes mixed escapes with lowercase slash": {
			value:    "api%2fv1%5Bid%5D",
			opts:     UnescapeOptions{Mode: UnescapeAllExceptSlash},
			expected: "api%2fv1[id]",
		},
		"all except slash performs single pass": {
			value:    "%2561",
			opts:     UnescapeOptions{Mode: UnescapeAllExceptSlash},
			expected: "%61",
		},
		"unreserved leaves unencoded content unchanged": {
			value:    "/api/admin",
			opts:     UnescapeOptions{Mode: UnescapeUnreserved},
			expected: "/api/admin",
		},
		"unreserved decodes lowercase letter": {
			value:    "/api/%61dmin",
			opts:     UnescapeOptions{Mode: UnescapeUnreserved},
			expected: "/api/admin",
		},
		"unreserved decodes uppercase hex": {
			value:    "/api/%41DMIN",
			opts:     UnescapeOptions{Mode: UnescapeUnreserved},
			expected: "/api/ADMIN",
		},
		"unreserved decodes digits": {
			value:    "/v%31/users",
			opts:     UnescapeOptions{Mode: UnescapeUnreserved},
			expected: "/v1/users",
		},
		"unreserved decodes punctuation": {
			value:    "/%2D%2E%5F%7E",
			opts:     UnescapeOptions{Mode: UnescapeUnreserved},
			expected: "/-._~",
		},
		"unreserved preserves uppercase encoded slash": {
			value:    "/foo%2Fbar",
			opts:     UnescapeOptions{Mode: UnescapeUnreserved},
			expected: "/foo%2Fbar",
		},
		"unreserved preserves lowercase encoded slash": {
			value:    "/foo%2fbar",
			opts:     UnescapeOptions{Mode: UnescapeUnreserved},
			expected: "/foo%2fbar",
		},
		"unreserved decodes URL characters without decoding reserved delimiters": {
			value:    "/%68%74%74%70%73%3A%2F%2Fexample.com%3Fx%3D%31",
			opts:     UnescapeOptions{Mode: UnescapeUnreserved},
			expected: "/https%3A%2F%2Fexample.com%3Fx%3D1",
		},
		"unreserved preserves brackets": {
			value:    "/foo%5Bbar%5D",
			opts:     UnescapeOptions{Mode: UnescapeUnreserved},
			expected: "/foo%5Bbar%5D",
		},
		"unreserved preserves encoded percent": {
			value:    "/foo%2561",
			opts:     UnescapeOptions{Mode: UnescapeUnreserved},
			expected: "/foo%2561",
		},
		"unreserved decodes characters following separately encoded percent": {
			value:    "%25%36%31",
			opts:     UnescapeOptions{Mode: UnescapeUnreserved},
			expected: "%2561",
		},
		"unreserved decodes only eligible characters in mixed value": {
			value:    "/foo%2F%62ar%3Fx%3D%31",
			opts:     UnescapeOptions{Mode: UnescapeUnreserved},
			expected: "/foo%2Fbar%3Fx%3D1",
		},
		"no escapes": {
			value:    "api/v1/resource",
			opts:     UnescapeOptions{Mode: UnescapeAll},
			expected: "api/v1/resource",
		},
		"incomplete escape": {
			value:    "api%2",
			opts:     UnescapeOptions{Mode: UnescapeAll},
			expected: "api%2",
		},
		"invalid escape": {
			value:    "api%ZZv1",
			opts:     UnescapeOptions{Mode: UnescapeAll},
			expected: "api%ZZv1",
		},
		"malformed sequences remain after valid escape": {
			value:    "api%61%ZZ%2",
			opts:     UnescapeOptions{Mode: UnescapeAll},
			expected: "apia%ZZ%2",
		},
		"unknown mode preserves escapes": {
			value:    "api%2Fv1%5Bid%5D",
			opts:     UnescapeOptions{Mode: UnescapeMode(255)},
			expected: "api%2Fv1%5Bid%5D",
		},
	} {
		t.Run(uc, func(t *testing.T) {
			result := PathUnescape(tc.value, tc.opts)

			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestPathUnescapeSinglePass(t *testing.T) {
	t.Parallel()

	for value := range 256 {
		for _, format := range []string{"%%%02X", "%%%02x"} {
			escaped := fmt.Sprintf(format, value)
			doubleEncoded := "%25" + escaped[1:]

			assert.Equal(
				t,
				escaped,
				PathUnescape(
					doubleEncoded,
					UnescapeOptions{Mode: UnescapeAll},
				),
				"value=%02X format=%s",
				value,
				format,
			)

			assert.Equal(
				t,
				escaped,
				PathUnescape(
					doubleEncoded,
					UnescapeOptions{Mode: UnescapeAllExceptSlash},
				),
				"value=%02X format=%s",
				value,
				format,
			)

			assert.Equal(
				t,
				doubleEncoded,
				PathUnescape(
					doubleEncoded,
					UnescapeOptions{Mode: UnescapeUnreserved},
				),
				"value=%02X format=%s",
				value,
				format,
			)
		}
	}
}

func TestEscapedPath(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		value    *url.URL
		expected string
	}{
		"without raw path": {
			value: &url.URL{
				Path: "/api/v1/resource",
			},
			expected: "/api/v1/resource",
		},
		"without raw path requiring escaping": {
			value: &url.URL{
				Path: "/api/a b",
			},
			expected: "/api/a%20b",
		},
		"preserves valid encoded slash": {
			value: &url.URL{
				Path:    "/files/a/b",
				RawPath: "/files/a%2Fb",
			},
			expected: "/files/a%2Fb",
		},
		"preserves valid encoded dot segments": {
			value: &url.URL{
				Path:    "/admin/../public/x",
				RawPath: "/admin/%2e%2e%2fpublic/x",
			},
			expected: "/admin/%2e%2e%2fpublic/x",
		},
		"escapes invalid byte while preserving encoded dot segments": {
			value: &url.URL{
				Path:    "/admin/../public/x|",
				RawPath: "/admin/%2e%2e%2fpublic/x|",
			},
			expected: "/admin/%2e%2e%2fpublic/x%7C",
		},
		"escapes invalid byte while preserving encoded slash": {
			value: &url.URL{
				Path:    "/files/a/b|",
				RawPath: "/files/a%2Fb|",
			},
			expected: "/files/a%2Fb%7C",
		},
		"escapes multiple invalid bytes": {
			value: &url.URL{
				Path:    "/api/a b|c",
				RawPath: "/api/a b|c",
			},
			expected: "/api/a%20b%7Cc",
		},
		"escapes malformed percent sequence": {
			value: &url.URL{
				Path:    "/api/%ZZ/%2",
				RawPath: "/api/%ZZ/%2",
			},
			expected: "/api/%25ZZ/%252",
		},
		"escapes raw UTF-8 bytes": {
			value: &url.URL{
				Path:    "/café",
				RawPath: "/café",
			},
			expected: "/caf%C3%A9",
		},
	} {
		t.Run(uc, func(t *testing.T) {
			result := EscapedPath(tc.value)
			assert.Equal(t, tc.expected, result)

			decoded, err := url.PathUnescape(result)
			require.NoError(t, err)
			assert.Equal(t, tc.value.Path, decoded)

			// The produced value must be a valid RawPath hint. Otherwise a
			// later stdlib EscapedPath call could discard it again.
			normalized := &url.URL{
				Path:    tc.value.Path,
				RawPath: result,
			}
			assert.Equal(t, result, normalized.EscapedPath())
		})
	}
}
