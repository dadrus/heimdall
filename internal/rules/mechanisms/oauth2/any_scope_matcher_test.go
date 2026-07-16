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

func TestAnyScopeMatcherMatch(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		matcher        AnyScopeMatcher
		providedScopes []string
		assert         func(t *testing.T, err error)
	}{
		"matches when the first required scope is present": {
			matcher: mustAnyScopeMatcher(t, []string{"read", "write"}, func(scopes []string) (ScopesMatcher, error) {
				return ExactScopeStrategyMatcher(scopes), nil
			}),
			providedScopes: []string{"read"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"matches when only a later required scope is present": {
			matcher: mustAnyScopeMatcher(t, []string{"read", "write"}, func(scopes []string) (ScopesMatcher, error) {
				return ExactScopeStrategyMatcher(scopes), nil
			}),
			providedScopes: []string{"write"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"matches when a provided hierarchical scope includes a required scope": {
			matcher: mustAnyScopeMatcher(t, []string{"orders.read", "inventory.read"}, func(scopes []string) (ScopesMatcher, error) {
				return HierarchicScopeStrategyMatcher(scopes), nil
			}),
			providedScopes: []string{"inventory"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"matches when a provided wildcard scope includes a required scope": {
			matcher: mustAnyScopeMatcher(t, []string{"orders.read", "inventory.read"}, func(scopes []string) (ScopesMatcher, error) {
				return WildcardScopeStrategyMatcher(scopes), nil
			}),
			providedScopes: []string{"orders.*"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"doesn't match when none of the required scopes is present": {
			matcher: mustAnyScopeMatcher(t, []string{"read", "write"}, func(scopes []string) (ScopesMatcher, error) {
				return ExactScopeStrategyMatcher(scopes), nil
			}),
			providedScopes: []string{"profile"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)

				var mismatch *ScopeMismatchError
				require.ErrorAs(t, err, &mismatch)
				require.ElementsMatch(t, []string{"read", "write"}, mismatch.RequiredScopes())
				require.Empty(t, mismatch.MissingScopes())
			},
		},
		"matches if no required scopes are defined": {
			matcher: mustAnyScopeMatcher(t, []string{}, func(scopes []string) (ScopesMatcher, error) {
				return ExactScopeStrategyMatcher(scopes), nil
			}),
			providedScopes: []string{"profile"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			err := tc.matcher.Match(tc.providedScopes)

			tc.assert(t, err)
		})
	}
}

func mustAnyScopeMatcher(t *testing.T, required []string, createMatcher scopeMatcherFactory) AnyScopeMatcher {
	t.Helper()

	matcher, err := NewAnyScopeMatcher(required, createMatcher)
	require.NoError(t, err)

	return matcher
}
