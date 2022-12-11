package extractors

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
)

func TestExtractQueryParameter(t *testing.T) {
	t.Parallel()

	// GIVEN
	queryParam := "test_param"
	queryParamValue := "foo"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "foobar.local", nil)
	require.NoError(t, err)

	ctx := &mocks.MockContext{}
	ctx.On("RequestQueryParameter", queryParam).Return(queryParamValue)

	strategy := QueryParameterExtractStrategy{Name: queryParam}

	// WHEN
	val, err := strategy.GetAuthData(ctx)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, queryParamValue, val.Value())

	val.ApplyTo(req)
	assert.Equal(t, queryParamValue, req.URL.Query().Get(queryParam))

	ctx.AssertExpectations(t)
}

func TestExtractNotExistingQueryParameterValue(t *testing.T) {
	t.Parallel()

	// GIVEN
	ctx := &mocks.MockContext{}
	ctx.On("RequestQueryParameter", mock.Anything).Return("")

	strategy := QueryParameterExtractStrategy{Name: "Test-Cookie"}

	// WHEN
	_, err := strategy.GetAuthData(ctx)

	// THEN
	assert.Error(t, err)
	assert.ErrorIs(t, err, heimdall.ErrArgument)

	ctx.AssertExpectations(t)
}
