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

package patternmatcher

import (
	"github.com/dlclark/regexp2"
	"github.com/ory/ladon/compiler"
)

type regexpMatcher struct {
	compiled *regexp2.Regexp
}

func newRegexMatcher(pattern string) (*regexpMatcher, error) {
	compiled, err := compiler.CompileRegex(pattern, '<', '>')
	if err != nil {
		return nil, err
	}

	return &regexpMatcher{compiled: compiled}, nil
}

func (m *regexpMatcher) Match(matchAgainst string) bool {
	// ignoring error as it will be set on timeouts, which basically is the same as match miss
	ok, _ := m.compiled.MatchString(matchAgainst)

	return ok
}
