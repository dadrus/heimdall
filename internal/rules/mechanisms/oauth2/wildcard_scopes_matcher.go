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

type WildcardScopeStrategyMatcher []string

func (m WildcardScopeStrategyMatcher) Match(scopes []string) error {
	for _, required := range m {
		if !m.doMatch(scopes, required) {
			return errorchain.NewWithMessagef(ErrScopeMatch, "required scope %s is missing", required)
		}
	}

	return nil
}

func (m WildcardScopeStrategyMatcher) doMatch(matchers []string, needle string) bool {
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
