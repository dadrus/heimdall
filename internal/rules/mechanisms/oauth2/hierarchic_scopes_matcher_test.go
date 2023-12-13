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

func TestHierarchicScopeStrategy(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc             string
		requiredScopes HierarchicScopeStrategyMatcher
		providedScopes []string
		assert         func(t *testing.T, err error)
	}{
		{
			uc:             "empty required scopes match single provided scope",
			requiredScopes: HierarchicScopeStrategyMatcher{},
			providedScopes: []string{"foo.bar"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc:             "empty required scopes match multiple provided scopes",
			requiredScopes: HierarchicScopeStrategyMatcher{},
			providedScopes: []string{"foo.bar", "bar.foo"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc:             "empty required scopes do match empty provided scopes",
			requiredScopes: HierarchicScopeStrategyMatcher{},
			providedScopes: []string{"foo.bar", "bar.foo"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc:             "required scopes with single element match provided scopes with exact same single scope",
			requiredScopes: HierarchicScopeStrategyMatcher{"foo.bar"},
			providedScopes: []string{"foo.bar"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc:             "required scopes with single element matches provided scopes with a single scope on root level",
			requiredScopes: HierarchicScopeStrategyMatcher{"foo.bar"},
			providedScopes: []string{"foo"}, // foo includes foo.bar, foo.baz, foo.*, etc
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc:             "required scopes with single element doesn't match provided scopes with a single scope having required scope as prefix",
			requiredScopes: HierarchicScopeStrategyMatcher{"foo.bar"},
			providedScopes: []string{"foo.bar.baz"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			uc:             "required scopes with single element doesn't match empty provided scopes",
			requiredScopes: HierarchicScopeStrategyMatcher{"foo.bar"},
			providedScopes: []string{},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			uc:             "required scopes with multiple elements match provided scopes in hierarchy, which also include further scopes",
			requiredScopes: HierarchicScopeStrategyMatcher{"foo.bar", "bar.foo"},
			providedScopes: []string{"foo", "bar.foo", "baz"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			err := tc.requiredScopes.Match(tc.providedScopes)

			// THEN
			tc.assert(t, err)
		})
	}
}
