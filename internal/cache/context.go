package cache

import (
	"context"
)

type ctxKey struct{}

// WithContext returns a copy of ctx with cache associated. If a Cache instance
// is already in the context, the ctx is not updated.
func WithContext(ctx context.Context, cch Cache) context.Context {
	if known, ok := ctx.Value(ctxKey{}).(Cache); ok {
		if known == cch {
			// Do not store same cache.
			return ctx
		}
	}

	return context.WithValue(ctx, ctxKey{}, cch)
}

// Ctx returns the Cache associated with the ctx. If no cache is associated, an instance is
// returned, which does nothing.
func Ctx(ctx context.Context) Cache {
	if c, ok := ctx.Value(ctxKey{}).(Cache); ok {
		return c
	}

	return noopCache{}
}
