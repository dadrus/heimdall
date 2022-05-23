package memory

import (
	"time"

	"github.com/jellydator/ttlcache/v3"
)

type InMemoryCache struct {
	c *ttlcache.Cache[string, any]
}

func New() *InMemoryCache {
	return &InMemoryCache{c: ttlcache.New[string, any]()}
}

func (c *InMemoryCache) Start() { c.c.Start() }

func (c *InMemoryCache) Stop() { c.c.Stop() }

func (c *InMemoryCache) Get(key string) any {
	item := c.c.Get(key)
	if item != nil && !item.IsExpired() {
		return item.Value()
	}

	return nil
}

func (c *InMemoryCache) Set(key string, value any, ttl time.Duration) { c.c.Set(key, value, ttl) }

func (c *InMemoryCache) Delete(key string) { c.c.Delete(key) }
