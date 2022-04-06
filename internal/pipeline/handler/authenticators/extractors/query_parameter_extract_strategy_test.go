package extractors

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/testsupport"
)

func TestExtractQueryParameter(t *testing.T) {
	t.Parallel()

	// GIVEN
	queryParam := "test_param"
	queryParamValue := "foo"
	req, err := http.NewRequest(http.MethodGet, "foobar.local", nil)
	require.NoError(t, err)

	ctx := &testsupport.MockContext{}
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
