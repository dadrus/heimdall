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

package stringx

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEqualFoldASCII(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		left  string
		right string
		want  bool
	}{
		"empty strings": {
			left:  "",
			right: "",
			want:  true,
		},
		"same lowercase": {
			left:  "forwarded",
			right: "forwarded",
			want:  true,
		},
		"same uppercase": {
			left:  "FORWARDED",
			right: "FORWARDED",
			want:  true,
		},
		"mixed case": {
			left:  "FoRwArDeD",
			right: "fOrWaRdEd",
			want:  true,
		},
		"ascii token with punctuation": {
			left:  "X-Forwarded-For",
			right: "x-forwarded-for",
			want:  true,
		},
		"different length": {
			left:  "for",
			right: "four",
			want:  false,
		},
		"different value": {
			left:  "for",
			right: "proto",
			want:  false,
		},
		"non letters unchanged": {
			left:  "for=192.0.2.1",
			right: "FOR=192.0.2.1",
			want:  true,
		},
		"unicode is not folded": {
			left:  "straße",
			right: "STRASSE",
			want:  false,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			assert.Equal(t, tc.want, EqualFoldASCII(tc.left, tc.right))
		})
	}
}
