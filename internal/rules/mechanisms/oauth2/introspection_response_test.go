// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
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

func TestIntrospectionResponseValidate(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		tokenType TokenType
		resp      IntrospectionResponse
		exp       Expectation
		assert    func(t *testing.T, err error)
	}{
		"token is not active": {
			resp: IntrospectionResponse{
				Active: false,
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "token is not active")
			},
		},
		"contents validation fails": {
			resp: IntrospectionResponse{
				Active: true,
				Claims: Claims{
					Issuer: "foo",
				},
			},
			exp: Expectation{
				TrustedIssuers: []string{"bar"},
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "issuer foo is not trusted")
			},
		},
		"contents validation succeeds": {
			resp: IntrospectionResponse{
				Active: true,
				Claims: Claims{
					Issuer:    "foo",
					TokenType: TypeBearer,
				},
			},
			exp: Expectation{
				TrustedIssuers: []string{"foo"},
				ScopesMatcher:  NoopMatcher{},
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			err := tc.resp.Validate(nil, tc.tokenType, "", tc.exp)

			tc.assert(t, err)
		})
	}
}
