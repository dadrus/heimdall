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
		assert         func(t *testing.T, err error, authData AuthData)
	}{
		{
			uc:            "unsupported content type",
			parameterName: "foobar",
			configureMocks: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().RequestHeader("Content-Type").Return("FooBar")
			},
			assert: func(t *testing.T, err error, authData AuthData) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "unsupported mime type")
			},
		},
		{
			uc:            "json body decoding error",
			parameterName: "foobar",
			configureMocks: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().RequestHeader("Content-Type").Return("application/json")
				ctx.EXPECT().RequestBody().Return([]byte("foo:?:bar"))
			},
			assert: func(t *testing.T, err error, authData AuthData) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "failed to decode")
			},
		},
		{
			uc:            "form url encoded body decoding error",
			parameterName: "foobar",
			configureMocks: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().RequestHeader("Content-Type").
					Return("application/x-www-form-urlencoded")
				ctx.EXPECT().RequestBody().Return([]byte("foo;"))
			},
			assert: func(t *testing.T, err error, authData AuthData) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "failed to decode")
			},
		},
		{
			uc:            "json encoded body does not contain required parameter",
			parameterName: "foobar",
			configureMocks: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().RequestHeader("Content-Type").
					Return("application/json")
				ctx.EXPECT().RequestBody().Return([]byte(`{"bar": "foo"}`))
			},
			assert: func(t *testing.T, err error, authData AuthData) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "no foobar parameter present")
			},
		},
		{
			uc:            "form url encoded body does not contain required parameter",
			parameterName: "foobar",
			configureMocks: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().RequestHeader("Content-Type").
					Return("application/x-www-form-urlencoded")
				ctx.EXPECT().RequestBody().Return([]byte(`foo=bar`))
			},
			assert: func(t *testing.T, err error, authData AuthData) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "no foobar parameter present")
			},
		},
		{
			uc:            "json encoded body contains required parameter multiple times",
			parameterName: "foobar",
			configureMocks: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().RequestHeader("Content-Type").
					Return("application/json")
				ctx.EXPECT().RequestBody().Return([]byte(`{"foobar": ["foo", "bar"]}`))
			},
			assert: func(t *testing.T, err error, authData AuthData) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "multiple times")
			},
		},
		{
			uc:            "form url encoded body contains required parameter multiple times",
			parameterName: "foobar",
			configureMocks: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().RequestHeader("Content-Type").
					Return("application/x-www-form-urlencoded")
				ctx.EXPECT().RequestBody().Return([]byte(`foobar=foo&foobar=bar`))
			},
			assert: func(t *testing.T, err error, authData AuthData) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "multiple times")
			},
		},
		{
			uc:            "json encoded body contains required parameter in wrong format #1",
			parameterName: "foobar",
			configureMocks: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().RequestHeader("Content-Type").
					Return("application/json")
				ctx.EXPECT().RequestBody().Return([]byte(`{"foobar": [1]}`))
			},
			assert: func(t *testing.T, err error, authData AuthData) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "unexpected type")
			},
		},
		{
			uc:            "json encoded body contains required parameter in wrong format #2",
			parameterName: "foobar",
			configureMocks: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().RequestHeader("Content-Type").
					Return("application/json")
				ctx.EXPECT().RequestBody().Return([]byte(`{"foobar": { "foo": "bar" }}`))
			},
			assert: func(t *testing.T, err error, authData AuthData) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "unexpected type")
			},
		},
		{
			uc:            "json encoded body contains required parameter",
			parameterName: "foobar",
			configureMocks: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().RequestHeader("Content-Type").
					Return("application/json")
				ctx.EXPECT().RequestBody().Return([]byte(`{"foobar": "foo"}`))
			},
			assert: func(t *testing.T, err error, authData AuthData) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "foo", authData.Value())
			},
		},
		{
			uc:            "form url encoded body contains required parameter",
			parameterName: "foobar",
			configureMocks: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().RequestHeader("Content-Type").
					Return("application/x-www-form-urlencoded")
				ctx.EXPECT().RequestBody().Return([]byte(`foobar=foo`))
			},
			assert: func(t *testing.T, err error, authData AuthData) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "foo", authData.Value())
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
