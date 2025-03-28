// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
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

package slicex

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSubtract(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		slice1   []string
		slice2   []string
		expected []string
	}{
		"both empty": {},
		"subtraction from an empty slice is an empty slice": {
			slice2: []string{"a", "b"},
		},
		"subtracting an empty slice from non empty one is the non empty one": {
			slice1:   []string{"a", "b"},
			expected: []string{"a", "b"},
		},
		"subtraction of two different slides is the first slide": {
			slice1:   []string{"a", "b"},
			slice2:   []string{"c", "d"},
			expected: []string{"a", "b"},
		},
		"subtraction of intersecting slides results in a slide with elements present in the first slide," +
			" but not in the second": {
			slice1:   []string{"a", "b", "c", "d"},
			slice2:   []string{"a", "c", "e", "f"},
			expected: []string{"b", "d"},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			result := Subtract(tc.slice1, tc.slice2)

			assert.EqualValues(t, tc.expected, result)
		})
	}
}
