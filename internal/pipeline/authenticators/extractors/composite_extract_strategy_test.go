package extractors

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dadrus/heimdall/internal/heimdall/mocks"
)

func TestCompositeExtractCookieValueWithoutPrefix(t *testing.T) {
	t.Parallel()

	// GIVEN
	headerName := "test-header"
	cookieName := "Test-Cookie"
	actualValue := "foo"

	ctx := &mocks.MockContext{}
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
	headerSchema := "bar:"
	actualValue := "foo"

	ctx := &mocks.MockContext{}
	ctx.On("RequestHeader", headerName).Return(headerSchema + " " + actualValue)
	ctx.On("RequestQueryParameter", queryParamName).Return("")

	strategy := CompositeExtractStrategy{
		QueryParameterExtractStrategy{Name: queryParamName},
		HeaderValueExtractStrategy{Name: headerName, Schema: headerSchema},
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
	headerSchema := "bar:"
	actualValue := "foo"

	ctx := &mocks.MockContext{}
	ctx.On("RequestHeader", headerName).Return(headerSchema + " " + actualValue)

	strategy := CompositeExtractStrategy{
		HeaderValueExtractStrategy{Name: headerName, Schema: headerSchema},
		QueryParameterExtractStrategy{Name: queryParamName},
	}

	// WHEN
	val, err := strategy.GetAuthData(ctx)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, actualValue, val.Value())
	ctx.AssertExpectations(t)
}
