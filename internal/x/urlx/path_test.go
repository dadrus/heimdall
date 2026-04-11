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
