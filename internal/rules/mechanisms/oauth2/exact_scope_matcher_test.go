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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExactScopeMatcherMatch(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		requiredScopes ExactScopeStrategyMatcher
		providedScopes []string
		assert         func(t *testing.T, err error)
	}{
		"doesn't match if only first scope is present": {
			requiredScopes: ExactScopeStrategyMatcher{"foo.bar.baz", "foo.bar"},
			providedScopes: []string{"foo.bar.baz"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		"doesn't match if only second scope is present": {
			requiredScopes: ExactScopeStrategyMatcher{"foo.bar.baz", "foo.bar"},
			providedScopes: []string{"foo.bar"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		"matches when all required scopes are present": {
			requiredScopes: ExactScopeStrategyMatcher{"foo.bar.baz", "foo.bar"},
			providedScopes: []string{"foo.bar.baz", "foo.bar"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"matches when more than all required scopes are present": {
			requiredScopes: ExactScopeStrategyMatcher{"foo.bar.baz", "foo.bar"},
			providedScopes: []string{"foo.bar.baz", "foo.bar", "baz.baz"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"doesn't match when no required scopes are present": {
			requiredScopes: ExactScopeStrategyMatcher{"foo.bar.baz", "foo.bar"},
			providedScopes: []string{},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		"doesn't match not included scope": {
			requiredScopes: ExactScopeStrategyMatcher{"foo.bar.baz", "foo.bar"},
			providedScopes: []string{"baz.baz"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		"matches if no required scopes are defined": {
			requiredScopes: ExactScopeStrategyMatcher{},
			providedScopes: []string{"baz.baz"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// WHEN
			err := tc.requiredScopes.Match(tc.providedScopes)

			// THEN
			tc.assert(t, err)
		})
	}
}
