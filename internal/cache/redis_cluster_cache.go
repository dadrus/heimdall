// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"context"
	"time"

	redis "github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

//nolint:revive
type RedisClusterCache struct {
	c *redis.ClusterClient
}

type RedisClusterConfig struct {
	Addrs          []string    `mapstructure:"addrs"            validate:"required,gt=0"`
	Username       string      `mapstructure:"username"`
	Password       string      `mapstructure:"password"`
	TLS            *config.TLS `mapstructure:"tls"`
	AdditionalCa   string      `mapstructure:"additional_ca"`
	ReadOnly       bool        `mapstructure:"read_only"`
	RouteByLatency bool        `mapstructure:"route_by_latency"`
	RouteRandomly  bool        `mapstructure:"route_randomly"`
}

// by intention. Used only during application bootstrap.
func init() { // nolint: gochecknoinits
	registerCacheTypeFactory(
		func(typ string, conf *config.Configuration) (bool, Cache, error) {
			if typ != CacheRedisCluster {
				return false, nil, nil
			}

			cache, err := NewRedisClusterCache(conf)

			return true, cache, err
		})
}

// Redis Cluster implementation of the Cache interface.
func NewRedisClusterCache(conf *config.Configuration) (*RedisClusterCache, error) {
	rawConf := conf.Cache.Config

	var redisCfg RedisClusterConfig

	if err := decodeConfig(rawConf, &redisCfg); err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"failed decoding redis cache config").CausedBy(err)
	}

	if err := validation.ValidateStruct(&redisCfg); err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"failed validating redis cache config").CausedBy(err)
	}

	opt := &redis.ClusterOptions{
		ClientName:     "heimdall-cluster-client",
		Addrs:          redisCfg.Addrs,
		Username:       redisCfg.Username, // use your Redis user. More info https://redis.io/docs/management/security/acl/
		Password:       redisCfg.Password,
		ReadOnly:       redisCfg.ReadOnly,
		RouteByLatency: redisCfg.RouteByLatency,
		RouteRandomly:  redisCfg.RouteRandomly,
	}

	if redisCfg.TLS != nil && len(redisCfg.TLS.KeyStore.Path) != 0 {
		tlsConfig, err := configureTLS(redisCfg.TLS, redisCfg.AdditionalCa)

		if err == nil {
			opt.TLSConfig = tlsConfig
		} else {
			return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
				"failed configuring tls for redis cache").CausedBy(err)
		}
	}

	client := redis.NewClusterClient(opt)

	return &RedisClusterCache{c: client}, nil
}

// not used for Redis.
func (c *RedisClusterCache) Start(_ context.Context) error {
	return nil
}

// not used for Redis.
func (c *RedisClusterCache) Stop(_ context.Context) error {
	return nil
}

func (c *RedisClusterCache) Get(ctx context.Context, key string) any {
	val, err := c.c.Get(ctx, key).Result()
	if err != nil {
		zerolog.Ctx(ctx).Info().Err(err).Msg("Failed to fetch value from cache")

		return nil
	}

	return val
}

func (c *RedisClusterCache) Set(ctx context.Context, key string, value any, ttl time.Duration) {
	err := c.c.Set(ctx, key, value, ttl).Err()
	if err != nil {
		zerolog.Ctx(ctx).Info().Err(err).Msg("Failed to store value in cache")
	}
}

// remove a key.
func (c *RedisClusterCache) Delete(ctx context.Context, key string) {
	// UNLINK removes the key asynchroneously; so we are not blocking here.
	err := c.c.Unlink(ctx, key).Err()
	if err != nil {
		zerolog.Ctx(ctx).Info().Err(err).Msg("Failed to unlink value from cache")
	}
}

func (c *RedisClusterCache) Check(ctx context.Context) error {
	if err := c.c.Ping(ctx).Err(); err != nil {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"failed connect to redis cluster cache").CausedBy(err)
	}

	return nil
}
