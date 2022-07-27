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
		configureMocks func(t *testing.T, ctx *mocks.MockContext)
		assert         func(t *testing.T, err error, authData AuthData)
	}{
		{
			uc:            "unsupported content type",
			parameterName: "foobar",
			configureMocks: func(t *testing.T, ctx *mocks.MockContext) {
				t.Helper()

				ctx.On("RequestHeader", "Content-Type").Return("FooBar")
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
			configureMocks: func(t *testing.T, ctx *mocks.MockContext) {
				t.Helper()

				ctx.On("RequestHeader", "Content-Type").Return("application/json")
				ctx.On("RequestBody").Return([]byte("foo:?:bar"))
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
			configureMocks: func(t *testing.T, ctx *mocks.MockContext) {
				t.Helper()

				ctx.On("RequestHeader", "Content-Type").
					Return("application/x-www-form-urlencoded")
				ctx.On("RequestBody").Return([]byte("foo;"))
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
			configureMocks: func(t *testing.T, ctx *mocks.MockContext) {
				t.Helper()

				ctx.On("RequestHeader", "Content-Type").
					Return("application/json")
				ctx.On("RequestBody").Return([]byte(`{"bar": "foo"}`))
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
			configureMocks: func(t *testing.T, ctx *mocks.MockContext) {
				t.Helper()

				ctx.On("RequestHeader", "Content-Type").
					Return("application/x-www-form-urlencoded")
				ctx.On("RequestBody").Return([]byte(`foo=bar`))
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
			configureMocks: func(t *testing.T, ctx *mocks.MockContext) {
				t.Helper()

				ctx.On("RequestHeader", "Content-Type").
					Return("application/json")
				ctx.On("RequestBody").Return([]byte(`{"foobar": ["foo", "bar"]}`))
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
			configureMocks: func(t *testing.T, ctx *mocks.MockContext) {
				t.Helper()

				ctx.On("RequestHeader", "Content-Type").
					Return("application/x-www-form-urlencoded")
				ctx.On("RequestBody").Return([]byte(`foobar=foo&foobar=bar`))
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
			configureMocks: func(t *testing.T, ctx *mocks.MockContext) {
				t.Helper()

				ctx.On("RequestHeader", "Content-Type").
					Return("application/json")
				ctx.On("RequestBody").Return([]byte(`{"foobar": [1]}`))
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
			configureMocks: func(t *testing.T, ctx *mocks.MockContext) {
				t.Helper()

				ctx.On("RequestHeader", "Content-Type").
					Return("application/json")
				ctx.On("RequestBody").Return([]byte(`{"foobar": { "foo": "bar" }}`))
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
			configureMocks: func(t *testing.T, ctx *mocks.MockContext) {
				t.Helper()

				ctx.On("RequestHeader", "Content-Type").
					Return("application/json")
				ctx.On("RequestBody").Return([]byte(`{"foobar": "foo"}`))
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
			configureMocks: func(t *testing.T, ctx *mocks.MockContext) {
				t.Helper()

				ctx.On("RequestHeader", "Content-Type").
					Return("application/x-www-form-urlencoded")
				ctx.On("RequestBody").Return([]byte(`foobar=foo`))
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
			ctx := &mocks.MockContext{}
			tc.configureMocks(t, ctx)

			strategy := BodyParameterExtractStrategy{Name: tc.parameterName}

			// WHEN
			authData, err := strategy.GetAuthData(ctx)

			// THEN
			tc.assert(t, err, authData)
		})
	}
}
