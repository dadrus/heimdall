/*
 * Copyright © 2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author		Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @copyright 	2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 *
 */

package oauth2

import "strings"

func HierarchicScopeStrategy(haystack []string, needle string) bool {
	for _, this := range haystack {
		// foo == foo -> true
		if this == needle {
			return true
		}

		// picture.read > picture -> false (scope picture includes read, write, ...)
		if len(this) > len(needle) {
			continue
		}

		needles := strings.Split(needle, ".")
		haystack := strings.Split(this, ".")
		haystackLen := len(haystack) - 1

		for k, needle := range needles {
			if haystackLen < k {
				return true
			}

			current := haystack[k]
			if current != needle {
				break
			}
		}
	}

	return false
}

func ExactScopeStrategy(haystack []string, needle string) bool {
	for _, this := range haystack {
		if needle == this {
			return true
		}
	}

	return false
}

func WildcardScopeStrategy(matchers []string, needle string) bool {
	needleParts := strings.Split(needle, ".")

	for _, matcher := range matchers {
		matcherParts := strings.Split(matcher, ".")

		if len(matcherParts) > len(needleParts) {
			continue
		}

		var noteq bool

		for idx, char := range strings.Split(matcher, ".") {
			// this is the last item and the lengths are different
			if idx == len(matcherParts)-1 && len(matcherParts) != len(needleParts) {
				if char != "*" {
					noteq = true

					break
				}
			}

			if char == "*" && len(needleParts[idx]) > 0 {
				// pass because this satisfies the requirements
				continue
			} else if char != needleParts[idx] {
				noteq = true

				break
			}
		}

		if !noteq {
			return true
		}
	}

	return false
}
