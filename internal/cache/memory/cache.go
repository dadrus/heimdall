package memory

import (
	"time"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/jellydator/ttlcache/v3"
)

type inMemoryCache struct {
	c *ttlcache.Cache[string, any]
}

func New() cache.Cache {
	return &inMemoryCache{c: ttlcache.New[string, any]()}
}

func (c *inMemoryCache) Start() { c.c.Start() }

func (c *inMemoryCache) Stop() { c.c.Stop() }

func (c *inMemoryCache) Get(key string) any {
	item := c.c.Get(key)
	if item != nil && !item.IsExpired() {
		return item.Value()
	}

	return nil
}

func (c *inMemoryCache) Set(key string, value any, ttl time.Duration) {
	c.c.Set(key, value, ttl)
}

func (c *inMemoryCache) Delete(key string) {
	c.c.Delete(key)
}
