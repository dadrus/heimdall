package extractors

import (
	"testing"

	"github.com/dadrus/heimdall/test"
	"github.com/stretchr/testify/assert"
)

func TestExtractQueryParameterWithoutPrefix(t *testing.T) {
	// GIVEN
	queryParameter := "test_param"
	actualValue := "foo"
	mock := &test.MockAuthDataSource{}
	mock.On("Query", queryParameter).Return(actualValue)
	c := QueryParameterExtractStrategy{Name: queryParameter}

	// WHEN
	val, err := c.GetAuthData(mock)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, actualValue, val)
	mock.AssertExpectations(t)
}

func TestExtractQueryParameterWithPrefix(t *testing.T) {
	// GIVEN
	queryParameter := "test_param"
	valuePrefix := "bar:"
	actualValue := "foo"
	mock := &test.MockAuthDataSource{}
	mock.On("Query", queryParameter).Return(valuePrefix + " " + actualValue)
	c := QueryParameterExtractStrategy{Name: queryParameter, Prefix: valuePrefix}

	// WHEN
	val, err := c.GetAuthData(mock)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, actualValue, val)
	mock.AssertExpectations(t)
}
