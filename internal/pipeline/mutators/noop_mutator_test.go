package mutators

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/pipeline/testsupport"
)

func TestNoopMutatorExecution(t *testing.T) {
	t.Parallel()

	// GIVEN
	ctx := &testsupport.MockContext{}
	ctx.On("AppContext").Return(context.Background())

	mutator := newNoopMutator()

	// WHEN
	err := mutator.Execute(ctx, nil)

	// THEN
	require.NoError(t, err)
}

func TestCreateNoopMutatorFromPrototype(t *testing.T) {
	t.Parallel()

	// GIVEN
	prototype := newNoopMutator()

	// WHEN
	mut1, err1 := prototype.WithConfig(nil)
	mut2, err2 := prototype.WithConfig(map[any]any{"foo": "bar"})

	// THEN
	assert.NoError(t, err1)
	assert.Equal(t, prototype, mut1)

	assert.NoError(t, err2)
	assert.Equal(t, prototype, mut2)
}
