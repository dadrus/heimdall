package cache

import (
	"context"
)

type ctxKey struct{}

// WithContext returns a copy of ctx with cache associated. If a Cache instance
// is already in the context, the context is not updated.
//
// For instance, to make use of the cache in the context, use this
// notation:
//
//     ctx := r.Context()
//     cch := cache.Ctx(ctx)
//     val, ok := cch.Get("some key")
//     use val and ok
func (c *Cache) WithContext(ctx context.Context) context.Context {
	if known, ok := ctx.Value(ctxKey{}).(*Cache); ok {
		if known == c {
			// Do not store same cache.
			return ctx
		}
	}

	return context.WithValue(ctx, ctxKey{}, c)
}

// Ctx returns the Cache associated with the ctx. If no cache is associated, nil is returned.
func Ctx(ctx context.Context) *Cache {
	if c, ok := ctx.Value(ctxKey{}).(*Cache); ok {
		return c
	}

	return nil
}
