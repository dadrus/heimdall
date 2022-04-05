package extractors

import (
	"testing"

	"github.com/dadrus/heimdall/internal/testsupport"
	"github.com/stretchr/testify/assert"
)

func TestCompositeExtractCookieValueWithoutPrefix(t *testing.T) {
	t.Parallel()

	// GIVEN
	formParamName := "test_param"
	cookieName := "Test-Cookie"
	actualValue := "foo"

	ctx := &testsupport.MockContext{}
	ctx.On("RequestCookie", cookieName).Return(actualValue)
	ctx.On("RequestFormParameter", formParamName).Return("")

	strategy := CompositeExtractStrategy{
		FormParameterExtractStrategy{Name: formParamName},
		CookieValueExtractStrategy{Name: cookieName},
	}

	// WHEN
	val, err := strategy.GetAuthData(ctx)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, actualValue, val)
	ctx.AssertExpectations(t)
}

func TestCompositeExtractHeaderValueWithPrefix(t *testing.T) {
	t.Parallel()

	// GIVEN
	headerName := "Test-Header"
	queryParamName := "test_param"
	valuePrefix := "bar:"
	actualValue := "foo"

	ctx := &testsupport.MockContext{}
	ctx.On("RequestHeader", headerName).Return(valuePrefix + " " + actualValue)
	ctx.On("RequestQueryParameter", queryParamName).Return("")

	strategy := CompositeExtractStrategy{
		QueryParameterExtractStrategy{Name: queryParamName},
		HeaderValueExtractStrategy{Name: headerName, Prefix: valuePrefix},
	}

	// WHEN
	val, err := strategy.GetAuthData(ctx)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, actualValue, val)
	ctx.AssertExpectations(t)
}

func TestCompositeExtractStrategyOrder(t *testing.T) {
	t.Parallel()

	// GIVEN
	headerName := "Test-Header"
	queryParamName := "test_param"
	valuePrefix := "bar:"
	actualValue := "foo"

	ctx := &testsupport.MockContext{}
	ctx.On("RequestHeader", headerName).Return(valuePrefix + " " + actualValue)

	strategy := CompositeExtractStrategy{
		HeaderValueExtractStrategy{Name: headerName, Prefix: valuePrefix},
		QueryParameterExtractStrategy{Name: queryParamName},
	}

	// WHEN
	val, err := strategy.GetAuthData(ctx)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, actualValue, val)
	ctx.AssertExpectations(t)
}
