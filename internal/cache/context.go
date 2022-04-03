package cache

import (
	"context"
	"time"
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

type noopCache struct{}

func (c noopCache) Start() {}

func (c noopCache) Stop() {}

func (c noopCache) Get(_ string) any { return nil }

func (c noopCache) Set(_ string, _ any, _ time.Duration) {}

func (c noopCache) Delete(_ string) {}
