package extractors

import (
	"testing"

	"github.com/dadrus/heimdall/internal/pipeline/handler"
	"github.com/stretchr/testify/assert"
)

func TestCompositeExtractCookieValueWithoutPrefix(t *testing.T) {
	t.Parallel()

	// GIVEN
	headerName := "test-header"
	cookieName := "Test-Cookie"
	actualValue := "foo"

	ctx := &handler.MockContext{}
	ctx.On("RequestCookie", cookieName).Return(actualValue)
	ctx.On("RequestHeader", headerName).Return("")

	strategy := CompositeExtractStrategy{
		HeaderValueExtractStrategy{Name: headerName},
		CookieValueExtractStrategy{Name: cookieName},
	}

	// WHEN
	val, err := strategy.GetAuthData(ctx)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, actualValue, val.Value())
	ctx.AssertExpectations(t)
}

func TestCompositeExtractHeaderValueWithPrefix(t *testing.T) {
	t.Parallel()

	// GIVEN
	headerName := "Test-Header"
	queryParamName := "test_param"
	valuePrefix := "bar:"
	actualValue := "foo"

	ctx := &handler.MockContext{}
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
	assert.Equal(t, actualValue, val.Value())
	ctx.AssertExpectations(t)
}

func TestCompositeExtractStrategyOrder(t *testing.T) {
	t.Parallel()

	// GIVEN
	headerName := "Test-Header"
	queryParamName := "test_param"
	valuePrefix := "bar:"
	actualValue := "foo"

	ctx := &handler.MockContext{}
	ctx.On("RequestHeader", headerName).Return(valuePrefix + " " + actualValue)

	strategy := CompositeExtractStrategy{
		HeaderValueExtractStrategy{Name: headerName, Prefix: valuePrefix},
		QueryParameterExtractStrategy{Name: queryParamName},
	}

	// WHEN
	val, err := strategy.GetAuthData(ctx)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, actualValue, val.Value())
	ctx.AssertExpectations(t)
}
