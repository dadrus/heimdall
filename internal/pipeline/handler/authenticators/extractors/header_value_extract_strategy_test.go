package extractors

import (
	"testing"

	"github.com/dadrus/heimdall/internal/testsupport"
	"github.com/stretchr/testify/assert"
)

func TestExtractHeaderValueWithoutPrefix(t *testing.T) {
	t.Parallel()

	// GIVEN
	headerName := "test_param"
	actualValue := "foo"

	ctx := &testsupport.MockContext{}
	ctx.On("RequestHeader", headerName).Return(actualValue)

	strategy := HeaderValueExtractStrategy{Name: headerName}

	// WHEN
	val, err := strategy.GetAuthData(ctx)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, actualValue, val)
	ctx.AssertExpectations(t)
}

func TestExtractHeaderValueWithPrefix(t *testing.T) {
	t.Parallel()

	// GIVEN
	headerName := "test_param"
	valuePrefix := "bar:"
	actualValue := "foo"

	ctx := &testsupport.MockContext{}
	ctx.On("RequestHeader", headerName).Return(valuePrefix + " " + actualValue)

	strategy := HeaderValueExtractStrategy{Name: headerName, Prefix: valuePrefix}

	// WHEN
	val, err := strategy.GetAuthData(ctx)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, actualValue, val)
	ctx.AssertExpectations(t)
}
