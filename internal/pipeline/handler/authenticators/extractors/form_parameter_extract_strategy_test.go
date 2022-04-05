package extractors

import (
	"testing"

	"github.com/dadrus/heimdall/internal/testsupport"
	"github.com/stretchr/testify/assert"
)

func TestExtractFormParameterWithoutPrefix(t *testing.T) {
	t.Parallel()

	// GIVEN
	paramName := "test_param"
	actualValue := "foo"

	ctx := &testsupport.MockContext{}
	ctx.On("RequestFormParameter", paramName).Return(actualValue)

	strategy := FormParameterExtractStrategy{Name: paramName}

	// WHEN
	val, err := strategy.GetAuthData(ctx)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, actualValue, val)
	ctx.AssertExpectations(t)
}

func TestExtractFormParameterWithPrefix(t *testing.T) {
	t.Parallel()

	// GIVEN
	paramName := "test_param"
	valuePrefix := "bar:"
	actualValue := "foo"

	ctx := &testsupport.MockContext{}
	ctx.On("RequestFormParameter", paramName).Return(valuePrefix + " " + actualValue)

	strategy := FormParameterExtractStrategy{Name: paramName, Prefix: valuePrefix}

	// WHEN
	val, err := strategy.GetAuthData(ctx)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, actualValue, val)
	ctx.AssertExpectations(t)
}
