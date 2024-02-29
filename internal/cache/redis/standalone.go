package redis

import (
	"time"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/watcher"
)

// by intention. Used only during application bootstrap.
func init() { // nolint: gochecknoinits
	cache.Register("redis", cache.FactoryFunc(NewStandaloneCache))
}

func NewStandaloneCache(conf map[string]any, cw watcher.Watcher) (cache.Cache, error) {
	type Config struct {
		baseConfig `mapstructure:",squash"`

		Address string `mapstructure:"address" validate:"required"`
		DB      int    `mapstructure:"db"`
	}

	cfg := Config{
		baseConfig: baseConfig{ClientCache: clientCache{TTL: 5 * time.Minute}}, //nolint:gomnd
	}

	err := decodeConfig(conf, &cfg)
	if err != nil {
		return nil, err
	}

	opts, err := cfg.clientOptions(cw)
	if err != nil {
		return nil, err
	}

	opts.InitAddress = []string{cfg.Address}
	opts.SelectDB = cfg.DB
	opts.ForceSingleClient = true

	return newRedisCache(opts, cfg.ClientCache.TTL)
}
