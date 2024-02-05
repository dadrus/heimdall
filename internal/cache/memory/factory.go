package memory

import "github.com/dadrus/heimdall/internal/cache"

// by intention. Used only during application bootstrap.
func init() { // nolint: gochecknoinits
	cache.Register("in-memory", &factory{})
}

type factory struct{}

func (*factory) Create(_ map[string]any) (cache.Cache, error) {
	return NewCache(), nil
}
