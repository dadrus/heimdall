package errorhandlers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
)

func TestDefaultErrorHandlerExecution(t *testing.T) {
	t.Parallel()

	// GIVEN
	ctx := &mocks.MockContext{}
	ctx.On("AppContext").Return(context.Background())
	ctx.On("SetPipelineError", heimdall.ErrConfiguration)

	errorHandler, err := newDefaultErrorHandler()
	require.NoError(t, err)

	// WHEN
	wasHandled, err := errorHandler.Execute(ctx, heimdall.ErrConfiguration)

	// THEN
	assert.True(t, wasHandled)
	assert.NoError(t, err)
}

func TestDefaultErrorHandlerPrototype(t *testing.T) {
	t.Parallel()

	// GIVEN
	prototype, err := newDefaultErrorHandler()
	require.NoError(t, err)

	// WHEN
	eh1, err1 := prototype.WithConfig(nil)
	eh2, err2 := prototype.WithConfig(map[string]any{"foo": "bar"})

	// THEN
	assert.NoError(t, err1)
	assert.Equal(t, prototype, eh1)

	assert.NoError(t, err2)
	assert.Equal(t, prototype, eh2)
}
