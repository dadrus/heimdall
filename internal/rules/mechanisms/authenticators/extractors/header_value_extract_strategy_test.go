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

package extractors

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
)

func TestExtractHeaderValue(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc             string
		strategy       HeaderValueExtractStrategy
		configureMocks func(t *testing.T, ctx *mocks.ContextMock)
		assert         func(t *testing.T, err error, authData string)
	}{
		{
			uc:       "header is present, schema is irrelevant",
			strategy: HeaderValueExtractStrategy{Name: "X-Test-Header"},
			configureMocks: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				fnt := mocks.NewRequestFunctionsMock(t)
				fnt.EXPECT().Header("X-Test-Header").Return("TestValue")

				ctx.EXPECT().Request().Return(&heimdall.Request{RequestFunctions: fnt})
			},
			assert: func(t *testing.T, err error, authData string) {
				t.Helper()

				assert.NoError(t, err)
				assert.Equal(t, "TestValue", authData)
			},
		},
		{
			uc:       "schema is required, header is present, but without any schema",
			strategy: HeaderValueExtractStrategy{Name: "X-Test-Header", Schema: "Foo"},
			configureMocks: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				fnt := mocks.NewRequestFunctionsMock(t)
				fnt.EXPECT().Header("X-Test-Header").Return("TestValue")

				ctx.EXPECT().Request().Return(&heimdall.Request{RequestFunctions: fnt})
			},
			assert: func(t *testing.T, err error, authData string) {
				t.Helper()

				assert.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "'Foo' schema")
			},
		},
		{
			uc:       "schema is required, header is present, but with different schema",
			strategy: HeaderValueExtractStrategy{Name: "X-Test-Header", Schema: "Foo"},
			configureMocks: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				fnt := mocks.NewRequestFunctionsMock(t)
				fnt.EXPECT().Header("X-Test-Header").Return("Bar TestValue")

				ctx.EXPECT().Request().Return(&heimdall.Request{RequestFunctions: fnt})
			},
			assert: func(t *testing.T, err error, authData string) {
				t.Helper()

				assert.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "'Foo' schema")
			},
		},
		{
			uc:       "header with required schema is present",
			strategy: HeaderValueExtractStrategy{Name: "X-Test-Header", Schema: "Foo"},
			configureMocks: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				fnt := mocks.NewRequestFunctionsMock(t)
				fnt.EXPECT().Header("X-Test-Header").Return("Foo TestValue")

				ctx.EXPECT().Request().Return(&heimdall.Request{RequestFunctions: fnt})
			},
			assert: func(t *testing.T, err error, authData string) {
				t.Helper()

				assert.NoError(t, err)
				assert.Equal(t, "TestValue", authData)
			},
		},
		{
			uc:       "header is not present at all",
			strategy: HeaderValueExtractStrategy{Name: "X-Test-Header", Schema: "Foo"},
			configureMocks: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				fnt := mocks.NewRequestFunctionsMock(t)
				fnt.EXPECT().Header("X-Test-Header").Return("")

				ctx.EXPECT().Request().Return(&heimdall.Request{RequestFunctions: fnt})
			},
			assert: func(t *testing.T, err error, authData string) {
				t.Helper()

				assert.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "no 'X-Test-Header' header")
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			ctx := mocks.NewContextMock(t)
			tc.configureMocks(t, ctx)

			// WHEN
			authData, err := tc.strategy.GetAuthData(ctx)

			// THEN
			tc.assert(t, err, authData)
		})
	}
}
