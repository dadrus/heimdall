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
	"testing"

	"github.com/stretchr/testify/assert"
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

func TestUnescape(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		value              string
		decodeEncodedSlash bool
		expected           string
	}{
		"decode slash on": {
			value:              "api%2Fv1",
			decodeEncodedSlash: true,
			expected:           "api/v1",
		},
		"decode slash off uppercase": {
			value:    "api%2Fv1",
			expected: "api%2Fv1",
		},
		"decode slash off lowercase": {
			value:    "api%2fv1",
			expected: "api%2fv1",
		},
		"decode non slash escapes": {
			value:    "foo%5Bid%5D",
			expected: "foo[id]",
		},
		"decode mixed preserve slash": {
			value:    "api%2Fv1%5Bid%5D",
			expected: "api%2Fv1[id]",
		},
		"decode mixed preserve slash lowercase": {
			value:    "api%2fv1%5Bid%5D",
			expected: "api%2fv1[id]",
		},
		"no escapes": {
			value:    "api/v1/resource",
			expected: "api/v1/resource",
		},
		"incomplete escape": {
			value:    "api%2",
			expected: "api%2",
		},
		"invalid escape": {
			value:    "api%ZZv1",
			expected: "api%ZZv1",
		},
	} {
		t.Run(uc, func(t *testing.T) {
			assert.Equal(t, tc.expected, Unescape(tc.value, tc.decodeEncodedSlash))
		})
	}
}
