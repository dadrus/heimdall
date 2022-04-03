package cache

import (
	"time"

	"github.com/jellydator/ttlcache/v3"
)

type Cache struct {
	c *ttlcache.Cache[string, any]
}

func New() *Cache {
	return &Cache{c: ttlcache.New[string, any]()}
}

func (c *Cache) Start() { c.c.Start() }

func (c *Cache) Stop() { c.c.Stop() }

func (c *Cache) Get(key string) any {
	item := c.c.Get(key)
	if item != nil && !item.IsExpired() {
		return item.Value()
	}

	return nil
}

func (c *Cache) Set(key string, value any, ttl time.Duration) {
	c.c.Set(key, value, ttl)
}
