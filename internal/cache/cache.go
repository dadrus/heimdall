package cache

import (
	"time"

	"github.com/jellydator/ttlcache/v3"
)

type Cache interface {
	Start()
	Stop()
	Get(key string) any
	Set(key string, value any, ttl time.Duration)
	Delete(key string)
}

type cacheImpl struct {
	c *ttlcache.Cache[string, any]
}

func New() Cache {
	return &cacheImpl{c: ttlcache.New[string, any]()}
}

func (c *cacheImpl) Start() { c.c.Start() }

func (c *cacheImpl) Stop() { c.c.Stop() }

func (c *cacheImpl) Get(key string) any {
	item := c.c.Get(key)
	if item != nil && !item.IsExpired() {
		return item.Value()
	}

	return nil
}

func (c *cacheImpl) Set(key string, value any, ttl time.Duration) {
	c.c.Set(key, value, ttl)
}

func (c *cacheImpl) Delete(key string) {
	c.c.Delete(key)
}
