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

import "strings"

//nolint:gocognit,gocyclo,gocyclo,cyclop,funlen
func PathHasDotSegments(path string) bool {
	iDot := strings.IndexByte(path, '.')
	iPct := strings.IndexByte(path, '%')
	iBsl := strings.IndexByte(path, '\\')

	idx := iDot
	if idx == -1 || (iPct != -1 && iPct < idx) {
		idx = iPct
	}

	if idx == -1 || (iBsl != -1 && iBsl < idx) {
		idx = iBsl
	}

	if idx == -1 {
		return false
	}

	segLen := 0
	for i := idx - 1; i >= 0 && path[i] != '/'; i-- {
		segLen++
	}

	dotCount := 0

	for i := idx; i < len(path); {
		switch path[i] {
		case '/', '\\':
			if (segLen == 1 && dotCount == 1) || (segLen == 2 && dotCount == 2) {
				return true
			}

			segLen = 0
			dotCount = 0
			i++
		case '.':
			segLen++
			dotCount++
			i++
		case '%':
			if i+2 >= len(path) {
				segLen++
				i++

				continue
			}

			h1 := path[i+1]
			h2 := path[i+2] | 0x20 //nolint:mnd

			switch {
			case h1 == '2' && h2 == 'e':
				segLen++
				dotCount++
				i += 3
			case h1 == '2' && h2 == 'f':
				if (segLen == 1 && dotCount == 1) || (segLen == 2 && dotCount == 2) {
					return true
				}

				segLen = 0
				dotCount = 0
				i += 3
			case h1 == '5' && h2 == 'c':
				if (segLen == 1 && dotCount == 1) || (segLen == 2 && dotCount == 2) {
					return true
				}

				segLen = 0
				dotCount = 0
				i += 3
			default:
				segLen++
				i++
			}
		default:
			segLen++
			i++
		}
	}

	return (segLen == 1 && dotCount == 1) || (segLen == 2 && dotCount == 2)
}
