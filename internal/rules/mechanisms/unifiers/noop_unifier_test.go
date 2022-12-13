package unifiers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall/mocks"
)

func TestNoopUnifierExecution(t *testing.T) {
	t.Parallel()

	// GIVEN
	ctx := &mocks.MockContext{}
	ctx.On("AppContext").Return(context.Background())

	unifier := newNoopUnifier()

	// WHEN
	err := unifier.Execute(ctx, nil)

	// THEN
	require.NoError(t, err)
}

func TestCreateNoopUnifierFromPrototype(t *testing.T) {
	t.Parallel()

	// GIVEN
	prototype := newNoopUnifier()

	// WHEN
	un1, err1 := prototype.WithConfig(nil)
	un2, err2 := prototype.WithConfig(map[string]any{"foo": "bar"})

	// THEN
	assert.NoError(t, err1)
	assert.Equal(t, prototype, un1)

	assert.NoError(t, err2)
	assert.Equal(t, prototype, un2)
}
