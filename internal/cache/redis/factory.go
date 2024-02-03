package redis

import "github.com/dadrus/heimdall/internal/cache"

// by intention. Used only during application bootstrap.
func init() { // nolint: gochecknoinits
	cache.Register("redis", &factory{})
}

type factory struct{}

func (*factory) Create(conf map[string]any) (cache.Cache, error) {
	return NewCache(conf)
}
