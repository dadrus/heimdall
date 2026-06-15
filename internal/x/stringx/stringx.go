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

package stringx

import "unsafe"

func ToString(b []byte) string { return unsafe.String(unsafe.SliceData(b), len(b)) }

func ToBytes(str string) []byte {
	return unsafe.Slice(unsafe.StringData(str), len(str))
}

// EqualFoldASCII reports whether s and t are equal under ASCII case-folding.
//
// Unlike strings.EqualFold, it does not perform Unicode case-folding resulting
// in better performance. It is intended for pure ASCII strings.
func EqualFoldASCII(s, t string) bool {
	if len(s) != len(t) {
		return false
	}

	for i := range len(t) {
		a := s[i]
		b := t[i]

		if a >= 'A' && a <= 'Z' {
			a += 'a' - 'A'
		}

		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}

		if a != b {
			return false
		}
	}

	return true
}
