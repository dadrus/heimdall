package exporters

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/sdk/trace"
)

func TestRegistryEmptyStore(t *testing.T) {
	t.Parallel()

	// GIVEN
	r := registry[trace.SpanExporter]{}

	// WHEN
	err := r.store("first", func(ctx context.Context) (trace.SpanExporter, error) { return nil, nil })

	// THEN
	require.NoError(t, err)
}

func TestRegistryNonEmptyStore(t *testing.T) {
	t.Parallel()

	// GIVEN
	r := registry[trace.SpanExporter]{}
	require.NoError(t, r.store("first", func(ctx context.Context) (trace.SpanExporter, error) { return nil, nil }))

	// WHEN
	err := r.store("second", func(ctx context.Context) (trace.SpanExporter, error) { return nil, nil })

	// THEN
	require.NoError(t, err)
}

func TestRegistryDuplicateStore(t *testing.T) {
	t.Parallel()

	// GIVEN
	r := registry[trace.SpanExporter]{}
	require.NoError(t, r.store("first", func(ctx context.Context) (trace.SpanExporter, error) { return nil, nil }))

	// WHEN
	err := r.store("first", func(ctx context.Context) (trace.SpanExporter, error) { return nil, nil })

	// THEN
	require.Error(t, err)
	require.ErrorIs(t, err, ErrDuplicateRegistration)
	assert.Contains(t, err.Error(), "first")
}

func TestRegistryEmptyLoad(t *testing.T) {
	t.Parallel()

	// GIVEN
	r := registry[trace.SpanExporter]{}

	// WHEN
	v, ok := r.load("non-existent")

	// THEN
	assert.False(t, ok, "empty registry should hold nothing")
	assert.Nil(t, v, "non-nil executor factory returned")
}

func TestRegistryExistentLoad(t *testing.T) {
	t.Parallel()

	// GIVEN
	reg := registry[trace.SpanExporter]{}

	require.NoError(t, reg.store("existent",
		func(ctx context.Context) (trace.SpanExporter, error) { return nil, errors.New("for test purpose") }))

	// WHEN
	value, ok := reg.load("existent")

	// THEN
	assert.True(t, ok, "registry should hold expected factory")
	assert.NotNil(t, value)

	_, err := value(context.Background())
	assert.Contains(t, err.Error(), "for test purpose")
}
