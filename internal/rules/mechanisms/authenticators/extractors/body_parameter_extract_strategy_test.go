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
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
)

func TestExtractBodyParameter(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc             string
		parameterName  string
		configureMocks func(t *testing.T, ctx *mocks.ContextMock)
		assert         func(t *testing.T, err error, authData string)
	}{
		{
			uc:            "body is a string",
			parameterName: "foobar",
			configureMocks: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				fnt := mocks.NewRequestFunctionsMock(t)
				fnt.EXPECT().Body().Return("foobar=foo")

				ctx.EXPECT().Request().Return(&heimdall.Request{RequestFunctions: fnt})
			},
			assert: func(t *testing.T, err error, _ string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "no usable body present")
			},
		},
		{
			uc:            "json body does not contain required parameter",
			parameterName: "foobar",
			configureMocks: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				fnt := mocks.NewRequestFunctionsMock(t)
				fnt.EXPECT().Body().Return(map[string]any{"foo": "bar"})

				ctx.EXPECT().Request().Return(&heimdall.Request{RequestFunctions: fnt})
			},
			assert: func(t *testing.T, err error, _ string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "no foobar parameter present")
			},
		},
		{
			uc:            "form url encoded body does not contain required parameter",
			parameterName: "foobar",
			configureMocks: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				fnt := mocks.NewRequestFunctionsMock(t)
				fnt.EXPECT().Body().Return(map[string]any{"foo": []any{"bar"}})

				ctx.EXPECT().Request().Return(&heimdall.Request{RequestFunctions: fnt})
			},
			assert: func(t *testing.T, err error, _ string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "no foobar parameter present")
			},
		},
		{
			uc:            "body contains required parameter multiple times #1",
			parameterName: "foobar",
			configureMocks: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				fnt := mocks.NewRequestFunctionsMock(t)
				fnt.EXPECT().Body().Return(map[string]any{"foobar": []any{"foo", "bar"}})

				ctx.EXPECT().Request().Return(&heimdall.Request{RequestFunctions: fnt})
			},
			assert: func(t *testing.T, err error, _ string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "multiple times")
			},
		},
		{
			uc:            "body contains required parameter multiple times #2",
			parameterName: "foobar",
			configureMocks: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				fnt := mocks.NewRequestFunctionsMock(t)
				fnt.EXPECT().Body().Return(map[string]any{"foobar": []string{"foo", "bar"}})

				ctx.EXPECT().Request().Return(&heimdall.Request{RequestFunctions: fnt})
			},
			assert: func(t *testing.T, err error, _ string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "multiple times")
			},
		},
		{
			uc:            "body contains required parameter in wrong format #1",
			parameterName: "foobar",
			configureMocks: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				fnt := mocks.NewRequestFunctionsMock(t)
				fnt.EXPECT().Body().Return(map[string]any{"foobar": []any{1}})

				ctx.EXPECT().Request().Return(&heimdall.Request{RequestFunctions: fnt})
			},
			assert: func(t *testing.T, err error, _ string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "unexpected type")
			},
		},
		{
			uc:            "body contains required parameter in wrong format #2",
			parameterName: "foobar",
			configureMocks: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				fnt := mocks.NewRequestFunctionsMock(t)
				fnt.EXPECT().Body().Return(map[string]any{"foobar": map[string]any{"foo": "bar"}})

				ctx.EXPECT().Request().Return(&heimdall.Request{RequestFunctions: fnt})
			},
			assert: func(t *testing.T, err error, _ string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "unexpected type")
			},
		},
		{
			uc:            "body contains required parameter #1",
			parameterName: "foobar",
			configureMocks: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				fnt := mocks.NewRequestFunctionsMock(t)
				fnt.EXPECT().Body().Return(map[string]any{"foobar": "foo"})

				ctx.EXPECT().Request().Return(&heimdall.Request{RequestFunctions: fnt})
			},
			assert: func(t *testing.T, err error, authData string) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "foo", authData)
			},
		},
		{
			uc:            "form url encoded body contains required parameter",
			parameterName: "foobar",
			configureMocks: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				fnt := mocks.NewRequestFunctionsMock(t)
				fnt.EXPECT().Body().Return(map[string]any{"foobar": []string{"foo"}})

				ctx.EXPECT().Request().Return(&heimdall.Request{RequestFunctions: fnt})
			},
			assert: func(t *testing.T, err error, authData string) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "foo", authData)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			ctx := mocks.NewContextMock(t)
			tc.configureMocks(t, ctx)

			strategy := BodyParameterExtractStrategy{Name: tc.parameterName}

			// WHEN
			authData, err := strategy.GetAuthData(ctx)

			// THEN
			tc.assert(t, err, authData)
		})
	}
}
