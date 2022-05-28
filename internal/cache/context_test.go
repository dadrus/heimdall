package cache

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/cache/memory"
)

func TestContextNoCacheConfigured(t *testing.T) {
	t.Parallel()

	// WHEN
	cch := Ctx(context.Background())

	// THEN
	require.NotNil(t, cch)
	assert.IsType(t, noopCache{}, cch)
}

func TestContextCacheConfigured(t *testing.T) {
	t.Parallel()

	// GIVEN
	ctx := WithContext(context.Background(), memory.New())

	// WHEN
	cch := Ctx(ctx)

	// THEN
	require.NotNil(t, cch)
	assert.IsType(t, &memory.InMemoryCache{}, cch)
}

func TestContextCacheIsNotConfiguredTwice(t *testing.T) {
	t.Parallel()

	// GIVEN
	cch1 := memory.New()
	cch2 := memory.New()

	ctx := context.Background()

	// WHEN
	ctx1 := WithContext(ctx, cch1)
	ctx2 := WithContext(ctx1, cch1)
	ctx3 := WithContext(ctx2, cch2)

	// THEN
	assert.Equal(t, ctx1, ctx2)
	assert.NotEqual(t, ctx2, ctx3)

	assert.Equal(t, cch1, Ctx(ctx1))
	assert.Equal(t, cch1, Ctx(ctx2))
	assert.Equal(t, cch2, Ctx(ctx3))
}
