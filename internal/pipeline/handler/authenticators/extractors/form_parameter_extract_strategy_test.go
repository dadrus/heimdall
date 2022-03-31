package extractors

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dadrus/heimdall/internal/test"
)

func TestExtractFormParameterWithoutPrefix(t *testing.T) {
	t.Parallel()

	// GIVEN
	paramName := "test_param"
	actualValue := "foo"
	mock := &test.MockAuthDataSource{}
	mock.On("Form", paramName).Return(actualValue)

	strategy := FormParameterExtractStrategy{Name: paramName}

	// WHEN
	val, err := strategy.GetAuthData(mock)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, actualValue, val)
	mock.AssertExpectations(t)
}

func TestExtractFormParameterWithPrefix(t *testing.T) {
	t.Parallel()

	// GIVEN
	paramName := "test_param"
	valuePrefix := "bar:"
	actualValue := "foo"
	mock := &test.MockAuthDataSource{}
	mock.On("Form", paramName).Return(valuePrefix + " " + actualValue)

	strategy := FormParameterExtractStrategy{Name: paramName, Prefix: valuePrefix}

	// WHEN
	val, err := strategy.GetAuthData(mock)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, actualValue, val)
	mock.AssertExpectations(t)
}
