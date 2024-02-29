package cache

import "github.com/dadrus/heimdall/internal/watcher"

type Factory interface {
	Create(conf map[string]any, cw watcher.Watcher) (Cache, error)
}

type FactoryFunc func(conf map[string]any, cw watcher.Watcher) (Cache, error)

func (f FactoryFunc) Create(conf map[string]any, cw watcher.Watcher) (Cache, error) {
	return f(conf, cw)
}
