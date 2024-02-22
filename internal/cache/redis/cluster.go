package redis

import (
	"time"

	"github.com/redis/rueidis"
	"github.com/redis/rueidis/rueidisotel"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap.
func init() { // nolint: gochecknoinits
	cache.Register("redis-cluster", cache.FactoryFunc(NewClusterCache))
}

func NewClusterCache(conf map[string]any) (cache.Cache, error) {
	type Config struct {
		baseConfig `mapstructure:",squash"`

		Nodes []string `mapstructure:"nodes" validate:"gt=0,dive,required"`
	}

	cfg := Config{
		baseConfig: baseConfig{ClientCache: clientCache{TTL: 5 * time.Minute}}, //nolint:gomnd
	}

	err := decodeConfig(conf, &cfg)
	if err != nil {
		return nil, err
	}

	opts := rueidis.ClientOption{
		ClientName:          "heimdall",
		InitAddress:         cfg.Nodes,
		ShuffleInit:         true,
		Username:            cfg.Credentials.Username,
		Password:            cfg.Credentials.Password,
		DisableCache:        cfg.ClientCache.Disabled,
		CacheSizeEachConn:   int(cfg.ClientCache.SizePerConnection),
		WriteBufferEachConn: int(cfg.BufferLimit.Write),
		ReadBufferEachConn:  int(cfg.BufferLimit.Read),
		ConnWriteTimeout:    cfg.Timeout.Write,
		MaxFlushDelay:       cfg.MaxFlushDelay,
	}

	if !cfg.TLS.Disabled {
		opts.TLSConfig, err = cfg.TLS.TLSConfig()
		if err != nil {
			return nil, errorchain.NewWithMessage(heimdall.ErrInternal,
				"failed creating tls configuration for Redis client").CausedBy(err)
		}
	}

	client, err := rueidisotel.NewClient(opts)
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed creating redis client").CausedBy(err)
	}

	return &redisCache{c: client, ttl: cfg.ClientCache.TTL}, nil
}
