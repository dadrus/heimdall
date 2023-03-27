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
	"errors"
)

var ErrUnsupportedPatternMatcher = errors.New("unsupported pattern matcher")

type PatternMatcher interface {
	Match(value string) bool
}

func NewPatternMatcher(typ, pattern string) (PatternMatcher, error) {
	switch typ {
	case "glob":
		return newGlobMatcher(pattern)
	case "regex":
		return newRegexMatcher(pattern)
	default:
		return nil, ErrUnsupportedPatternMatcher
	}
}
