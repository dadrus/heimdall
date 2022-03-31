package extractors

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dadrus/heimdall/internal/test"
)

func TestExtractCookieValueWithoutPrefix(t *testing.T) {
	t.Parallel()

	// GIVEN
	cookieName := "Test-Cookie"
	actualValue := "foo"
	mock := &test.MockAuthDataSource{}
	mock.On("Cookie", cookieName).Return(actualValue)

	strategy := CookieValueExtractStrategy{Name: cookieName}

	// WHEN
	val, err := strategy.GetAuthData(mock)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, actualValue, val)
	mock.AssertExpectations(t)
}

func TestExtractCookieValueWithPrefix(t *testing.T) {
	t.Parallel()

	// GIVEN
	cookieName := "Test-Cookie"
	valuePrefix := "bar:"
	actualValue := "foo"
	mock := &test.MockAuthDataSource{}
	mock.On("Cookie", cookieName).Return(valuePrefix + " " + actualValue)

	strategy := CookieValueExtractStrategy{Name: cookieName, Prefix: valuePrefix}

	// WHEN
	val, err := strategy.GetAuthData(mock)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, actualValue, val)
	mock.AssertExpectations(t)
}
