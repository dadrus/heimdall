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

func TestUnescapePathValue(t *testing.T) {
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
			assert.Equal(t, tc.expected, UnescapePathValue(tc.value, tc.decodeEncodedSlash))
		})
	}
}
