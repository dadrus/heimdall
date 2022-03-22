package extractors

import (
	"testing"

	"github.com/dadrus/heimdall/test"
	"github.com/stretchr/testify/assert"
)

func TestExtractCookieValueWithoutPrefix(t *testing.T) {
	// GIVEN
	cookieName := "Test-Cookie"
	actualValue := "foo"
	mock := &test.MockAuthDataSource{}
	mock.On("Cookie", cookieName).Return(actualValue)
	c := CookieValueExtractStrategy{Name: cookieName}

	// WHEN
	val, err := c.GetAuthData(mock)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, actualValue, val)
	mock.AssertExpectations(t)
}

func TestExtractCookieValueWithPrefix(t *testing.T) {
	// GIVEN
	cookieName := "Test-Cookie"
	valuePrefix := "bar:"
	actualValue := "foo"
	mock := &test.MockAuthDataSource{}
	mock.On("Cookie", cookieName).Return(valuePrefix + " " + actualValue)
	c := CookieValueExtractStrategy{Name: cookieName, Prefix: valuePrefix}

	// WHEN
	val, err := c.GetAuthData(mock)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, actualValue, val)
	mock.AssertExpectations(t)
}
