package redis

import (
	"time"

	"github.com/redis/rueidis"

	"github.com/dadrus/heimdall/internal/cache"
)

// by intention. Used only during application bootstrap.
func init() { // nolint: gochecknoinits
	cache.Register("redis-sentinel", cache.FactoryFunc(NewSentinelCache))
}

func NewSentinelCache(conf map[string]any) (cache.Cache, error) {
	type Config struct {
		baseConfig `mapstructure:",squash"`

		Nodes  []string `mapstructure:"nodes"  validate:"gt=0,dive,required"`
		Master string   `mapstructure:"master" validate:"required"`
		DB     int      `mapstructure:"db"`
	}

	cfg := Config{
		baseConfig: baseConfig{ClientCache: clientCache{TTL: 5 * time.Minute}}, //nolint:gomnd
	}

	err := decodeConfig(conf, &cfg)
	if err != nil {
		return nil, err
	}

	opts, err := cfg.clientOptions()
	if err != nil {
		return nil, err
	}

	opts.InitAddress = cfg.Nodes
	opts.ShuffleInit = true
	opts.SelectDB = cfg.DB
	opts.Sentinel = rueidis.SentinelOption{
		MasterSet: cfg.Master,
		Username:  cfg.Credentials.Username,
		Password:  cfg.Credentials.Password,
	}

	return newRedisCache(opts, cfg.ClientCache.TTL)
}
