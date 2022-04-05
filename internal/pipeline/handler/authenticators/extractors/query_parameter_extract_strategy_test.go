package extractors

import (
	"testing"

	"github.com/dadrus/heimdall/internal/testsupport"
	"github.com/stretchr/testify/assert"
)

func TestExtractQueryParameterWithoutPrefix(t *testing.T) {
	t.Parallel()

	// GIVEN
	queryParameter := "test_param"
	actualValue := "foo"
	
	ctx := &testsupport.MockContext{}
	ctx.On("RequestQueryParameter", queryParameter).Return(actualValue)

	strategy := QueryParameterExtractStrategy{Name: queryParameter}

	// WHEN
	val, err := strategy.GetAuthData(ctx)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, actualValue, val)
	ctx.AssertExpectations(t)
}

func TestExtractQueryParameterWithPrefix(t *testing.T) {
	t.Parallel()

	// GIVEN
	queryParameter := "test_param"
	valuePrefix := "bar:"
	actualValue := "foo"

	ctx := &testsupport.MockContext{}
	ctx.On("RequestQueryParameter", queryParameter).Return(valuePrefix + " " + actualValue)

	strategy := QueryParameterExtractStrategy{Name: queryParameter, Prefix: valuePrefix}

	// WHEN
	val, err := strategy.GetAuthData(ctx)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, actualValue, val)
	ctx.AssertExpectations(t)
}
