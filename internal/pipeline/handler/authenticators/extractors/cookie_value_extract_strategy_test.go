package extractors

import (
	"testing"

	"github.com/dadrus/heimdall/internal/testsupport"
	"github.com/stretchr/testify/assert"
)

func TestExtractCookieValueWithoutPrefix(t *testing.T) {
	t.Parallel()

	// GIVEN
	cookieName := "Test-Cookie"
	actualValue := "foo"

	ctx := &testsupport.MockContext{}
	ctx.On("RequestCookie", cookieName).Return(actualValue)

	strategy := CookieValueExtractStrategy{Name: cookieName}

	// WHEN
	val, err := strategy.GetAuthData(ctx)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, actualValue, val)
	ctx.AssertExpectations(t)
}

func TestExtractCookieValueWithPrefix(t *testing.T) {
	t.Parallel()

	// GIVEN
	cookieName := "Test-Cookie"
	valuePrefix := "bar:"
	actualValue := "foo"

	ctx := &testsupport.MockContext{}
	ctx.On("RequestCookie", cookieName).Return(valuePrefix + " " + actualValue)

	strategy := CookieValueExtractStrategy{Name: cookieName, Prefix: valuePrefix}

	// WHEN
	val, err := strategy.GetAuthData(ctx)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, actualValue, val)
	ctx.AssertExpectations(t)
}
