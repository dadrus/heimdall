package extractors

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
)

func TestExtractHeaderValue(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc             string
		strategy       HeaderValueExtractStrategy
		configureMocks func(t *testing.T, ctx *mocks.MockContext)
		assert         func(t *testing.T, err error, authData AuthData)
	}{
		{
			uc:       "header is present, schema is irrelevant",
			strategy: HeaderValueExtractStrategy{Name: "X-Test-Header"},
			configureMocks: func(t *testing.T, ctx *mocks.MockContext) {
				t.Helper()

				ctx.On("RequestHeader", "X-Test-Header").Return("TestValue")
			},
			assert: func(t *testing.T, err error, authData AuthData) {
				t.Helper()

				assert.NoError(t, err)
				assert.Equal(t, "TestValue", authData.Value())
			},
		},
		{
			uc:       "schema is required, header is present, but without any schema",
			strategy: HeaderValueExtractStrategy{Name: "X-Test-Header", Schema: "Foo"},
			configureMocks: func(t *testing.T, ctx *mocks.MockContext) {
				t.Helper()

				ctx.On("RequestHeader", "X-Test-Header").Return("TestValue")
			},
			assert: func(t *testing.T, err error, authData AuthData) {
				t.Helper()

				assert.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "'Foo' schema")
			},
		},
		{
			uc:       "schema is required, header is present, but with different schema",
			strategy: HeaderValueExtractStrategy{Name: "X-Test-Header", Schema: "Foo"},
			configureMocks: func(t *testing.T, ctx *mocks.MockContext) {
				t.Helper()

				ctx.On("RequestHeader", "X-Test-Header").Return("Bar TestValue")
			},
			assert: func(t *testing.T, err error, authData AuthData) {
				t.Helper()

				assert.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "'Foo' schema")
			},
		},
		{
			uc:       "header with required schema is present",
			strategy: HeaderValueExtractStrategy{Name: "X-Test-Header", Schema: "Foo"},
			configureMocks: func(t *testing.T, ctx *mocks.MockContext) {
				t.Helper()

				ctx.On("RequestHeader", "X-Test-Header").Return("Foo TestValue")
			},
			assert: func(t *testing.T, err error, authData AuthData) {
				t.Helper()

				assert.NoError(t, err)
				assert.Equal(t, "TestValue", authData.Value())
			},
		},
		{
			uc:       "header is not present at all",
			strategy: HeaderValueExtractStrategy{Name: "X-Test-Header", Schema: "Foo"},
			configureMocks: func(t *testing.T, ctx *mocks.MockContext) {
				t.Helper()

				ctx.On("RequestHeader", "X-Test-Header").Return("")
			},
			assert: func(t *testing.T, err error, authData AuthData) {
				t.Helper()

				assert.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "no 'X-Test-Header' header")
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			ctx := &mocks.MockContext{}
			tc.configureMocks(t, ctx)

			// WHEN
			authData, err := tc.strategy.GetAuthData(ctx)

			// THEN
			tc.assert(t, err, authData)
			ctx.AssertExpectations(t)
		})
	}
}

func TestApplyHeaderAuthDataToRequest(t *testing.T) {
	t.Parallel()

	// GIVEN
	headerName := "X-Test-Header"
	rawHeaderValue := "Foo Bar"
	headerValueWithoutSchema := "Bar"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "foobar.local", nil)
	require.NoError(t, err)

	authData := &headerAuthData{name: headerName, rawValue: rawHeaderValue, value: headerValueWithoutSchema}

	// WHEN
	authData.ApplyTo(req)

	// THEN
	assert.Equal(t, rawHeaderValue, req.Header.Get(headerName))
}
