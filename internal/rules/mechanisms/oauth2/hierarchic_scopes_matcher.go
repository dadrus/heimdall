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

package oauth2

import (
	"strings"

	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type HierarchicScopeStrategyMatcher []string

func (m HierarchicScopeStrategyMatcher) Match(scopes []string) error {
	for _, required := range m {
		if !m.doMatch(scopes, required) {
			return errorchain.NewWithMessagef(ErrScopeMatch, "required scope %s is missing", required)
		}
	}

	return nil
}

func (m HierarchicScopeStrategyMatcher) doMatch(haystack []string, needle string) bool {
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
