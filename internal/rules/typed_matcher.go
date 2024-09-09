// Copyright 2024 Dimitrij Drus <dadrus@gmx.de>
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

package rules

import (
	"errors"
	"regexp"

	"github.com/gobwas/glob"
)

var (
	ErrNoGlobPatternDefined  = errors.New("no glob pattern defined")
	ErrNoRegexPatternDefined = errors.New("no regex pattern defined")
)

type (
	typedMatcher interface {
		match(pattern string) bool
	}

	globMatcher struct {
		compiled glob.Glob
	}

	regexpMatcher struct {
		compiled *regexp.Regexp
	}

	exactMatcher struct {
		value string
	}
)

func (m *globMatcher) match(value string) bool {
	return m.compiled.Match(value)
}

func (m *regexpMatcher) match(matchAgainst string) bool {
	return m.compiled.MatchString(matchAgainst)
}

func (m *exactMatcher) match(value string) bool { return m.value == value }

func newGlobMatcher(pattern string, separator rune) (typedMatcher, error) {
	if len(pattern) == 0 {
		return nil, ErrNoGlobPatternDefined
	}

	compiled, err := glob.Compile(pattern, separator)
	if err != nil {
		return nil, err
	}

	return &globMatcher{compiled: compiled}, nil
}

func newRegexMatcher(pattern string) (typedMatcher, error) {
	if len(pattern) == 0 {
		return nil, ErrNoRegexPatternDefined
	}

	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	return &regexpMatcher{compiled: compiled}, nil
}

func newExactMatcher(value string) (typedMatcher, error) { return &exactMatcher{value: value}, nil }
