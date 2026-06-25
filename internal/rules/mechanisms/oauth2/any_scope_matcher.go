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

type AnyScopeMatcher struct {
	required []string
	matchers []ScopesMatcher
}

func NewAnyScopeMatcher(required []string, createMatcher scopeMatcherFactory) (AnyScopeMatcher, error) {
	matchers := make([]ScopesMatcher, len(required))

	for idx, scope := range required {
		matcher, err := createMatcher([]string{scope})
		if err != nil {
			return AnyScopeMatcher{}, err
		}

		matchers[idx] = matcher
	}

	return AnyScopeMatcher{required: required, matchers: matchers}, nil
}

func (m AnyScopeMatcher) Match(scopes []string) error {
	if len(m.required) == 0 {
		return nil
	}

	for _, matcher := range m.matchers {
		if err := matcher.Match(scopes); err == nil {
			return nil
		}
	}

	return NewScopeMismatchError(m.required, nil)
}
