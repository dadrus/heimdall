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

func TestRequiredWildcardScopeStrategyMatcher(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		requiredScopes RequiredWildcardScopeStrategyMatcher
		providedScopes []string
		assert         func(t *testing.T, err error)
	}{
		"configured wildcard matches concrete token scope": {
			requiredScopes: RequiredWildcardScopeStrategyMatcher{"documents.*"},
			providedScopes: []string{"documents.read"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"configured wildcard does not match another namespace": {
			requiredScopes: RequiredWildcardScopeStrategyMatcher{"documents.*"},
			providedScopes: []string{"reports.read"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		"configured wildcard on later required scope must also match": {
			requiredScopes: RequiredWildcardScopeStrategyMatcher{"documents.*", "reports.*"},
			providedScopes: []string{"documents.read"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		"matches if no required scopes are defined": {
			requiredScopes: RequiredWildcardScopeStrategyMatcher{},
			providedScopes: []string{"documents.read"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			err := tc.requiredScopes.Match(tc.providedScopes)

			tc.assert(t, err)
		})
	}
}
