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

package authorizers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateAuthorizerPrototypeUsingKnowType(t *testing.T) {
	t.Parallel()

	// there are 5 authorizers implemented, which should have been registered
	require.Len(t, authorizerTypeFactories, 4)

	for _, tc := range []struct {
		uc     string
		typ    string
		assert func(t *testing.T, err error, auth Authorizer)
	}{
		{
			uc:  "using known type",
			typ: AuthorizerAllow,
			assert: func(t *testing.T, err error, auth Authorizer) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, &allowAuthorizer{}, auth)
			},
		},
		{
			uc:  "using unknown type",
			typ: "foo",
			assert: func(t *testing.T, err error, _ Authorizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrUnsupportedAuthorizerType)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			auth, err := CreatePrototype(NewCreationContextMock(t), "foo", tc.typ, nil)

			// THEN
			tc.assert(t, err, auth)
		})
	}
}
