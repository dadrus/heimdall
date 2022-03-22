package extractors

import (
	"testing"

	"github.com/dadrus/heimdall/test"
	"github.com/stretchr/testify/assert"
)

func TestExtractHeaderValueWithoutPrefix(t *testing.T) {
	// GIVEN
	headerName := "test_param"
	actualValue := "foo"
	mock := &test.MockAuthDataSource{}
	mock.On("Header", headerName).Return(actualValue)
	c := HeaderValueExtractStrategy{Name: headerName}

	// WHEN
	val, err := c.GetAuthData(mock)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, actualValue, val)
	mock.AssertExpectations(t)
}

func TestExtractHeaderValueWithPrefix(t *testing.T) {
	// GIVEN
	headerName := "test_param"
	valuePrefix := "bar:"
	actualValue := "foo"
	mock := &test.MockAuthDataSource{}
	mock.On("Header", headerName).Return(valuePrefix + " " + actualValue)
	c := HeaderValueExtractStrategy{Name: headerName, Prefix: valuePrefix}

	// WHEN
	val, err := c.GetAuthData(mock)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, actualValue, val)
	mock.AssertExpectations(t)
}
