package extractors

import (
	"net/http"
	"testing"

	"github.com/dadrus/heimdall/internal/pipeline/handler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractHeaderValueWithoutPrefix(t *testing.T) {
	t.Parallel()

	// GIVEN
	headerName := "test_param"
	headerValue := "foo"
	req, err := http.NewRequest(http.MethodGet, "foobar.local", nil)
	require.NoError(t, err)

	ctx := &handler.MockContext{}
	ctx.On("RequestHeader", headerName).Return(headerValue)

	strategy := HeaderValueExtractStrategy{Name: headerName}

	// WHEN
	val, err := strategy.GetAuthData(ctx)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, headerValue, val.Value())

	val.ApplyTo(req)
	assert.Equal(t, headerValue, req.Header.Get(headerName))

	ctx.AssertExpectations(t)
}

func TestExtractHeaderValueWithPrefix(t *testing.T) {
	t.Parallel()

	// GIVEN
	headerName := "test_param"
	valuePrefix := "bar:"
	actualValue := "foo"
	req, err := http.NewRequest(http.MethodGet, "foobar.local", nil)
	require.NoError(t, err)

	ctx := &handler.MockContext{}
	ctx.On("RequestHeader", headerName).Return(valuePrefix + " " + actualValue)

	strategy := HeaderValueExtractStrategy{Name: headerName, Prefix: valuePrefix}

	// WHEN
	val, err := strategy.GetAuthData(ctx)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, actualValue, val.Value())

	val.ApplyTo(req)
	assert.Equal(t, actualValue, req.Header.Get(headerName))

	ctx.AssertExpectations(t)
}
