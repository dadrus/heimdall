package extractors

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dadrus/heimdall/internal/test"
)

func TestExtractHeaderValueWithoutPrefix(t *testing.T) {
	t.Parallel()

	// GIVEN
	headerName := "test_param"
	actualValue := "foo"
	mock := &test.MockAuthDataSource{}
	mock.On("Header", headerName).Return(actualValue)

	strategy := HeaderValueExtractStrategy{Name: headerName}

	// WHEN
	val, err := strategy.GetAuthData(mock)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, actualValue, val)
	mock.AssertExpectations(t)
}

func TestExtractHeaderValueWithPrefix(t *testing.T) {
	t.Parallel()

	// GIVEN
	headerName := "test_param"
	valuePrefix := "bar:"
	actualValue := "foo"
	mock := &test.MockAuthDataSource{}
	mock.On("Header", headerName).Return(valuePrefix + " " + actualValue)

	strategy := HeaderValueExtractStrategy{Name: headerName, Prefix: valuePrefix}

	// WHEN
	val, err := strategy.GetAuthData(mock)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, actualValue, val)
	mock.AssertExpectations(t)
}
