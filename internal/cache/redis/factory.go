package redis

import (
	"github.com/dadrus/heimdall/internal/cache"
)

// by intention. Used only during application bootstrap.
func init() { // nolint: gochecknoinits
	cache.Register("redis", factoryFunc(NewStandaloneCache))
	cache.Register("redis-cluster", factoryFunc(NewClusterCache))
	cache.Register("redis-sentinel", factoryFunc(NewClusterCache))
}

type factoryFunc func(conf map[string]any) (cache.Cache, error)

func (f factoryFunc) Create(conf map[string]any) (cache.Cache, error) {
	return f(conf)
}
