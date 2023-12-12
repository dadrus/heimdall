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
type RedisCache struct {
	c *redis.Client
}

type RedisConfig struct {
	Addr         string      `mapstructure:"addr"          validate:"required"`
	Username     string      `mapstructure:"username"`
	Password     string      `mapstructure:"password"`
	DB           int         `mapstructure:"db"`
	TLS          *config.TLS `mapstructure:"tls"`
	AdditionalCa string      `mapstructure:"additional_ca"`
}

// by intention. Used only during application bootstrap.
func init() { // nolint: gochecknoinits
	registerCacheTypeFactory(
		func(typ string, conf *config.Configuration) (bool, Cache, error) {
			if typ != CacheRedis {
				return false, nil, nil
			}

			cache, err := NewRedisCache(conf)

			if cache == nil {
				return false, nil, err
			}

			return true, cache, err
		})
}

// Redis implementation of the Cache interface.
func NewRedisCache(conf *config.Configuration) (*RedisCache, error) {
	rawConf := conf.Cache.Config

	var redisCfg RedisConfig

	if err := decodeConfig(rawConf, &redisCfg); err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"failed decoding redis cache config").CausedBy(err)
	}

	if err := validation.ValidateStruct(&redisCfg); err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"failed validating redis cache config").CausedBy(err)
	}

	opt := &redis.Options{
		ClientName: "heimdall",
		Addr:       redisCfg.Addr,
		Username:   redisCfg.Username, // use your Redis user. More info https://redis.io/docs/management/security/acl/
		Password:   redisCfg.Password,
		DB:         redisCfg.DB,
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

	client := redis.NewClient(opt)

	return &RedisCache{c: client}, nil
}

// not used for Redis.
func (c *RedisCache) Start(_ context.Context) error {
	return nil
}

// not used for Redis.
func (c *RedisCache) Stop(_ context.Context) error {
	return nil
}

func (c *RedisCache) Get(ctx context.Context, key string) any {
	val, err := c.c.Get(ctx, key).Result()
	if err != nil {
		zerolog.Ctx(ctx).Info().Err(err).Msg("Failed to fetch value from cache")

		return nil
	}

	return val
}

func (c *RedisCache) Set(ctx context.Context, key string, value any, ttl time.Duration) {
	err := c.c.Set(ctx, key, value, ttl).Err()
	if err != nil {
		zerolog.Ctx(ctx).Info().Err(err).Msg("Failed to store value in cache")
	}
}

// remove a key.
func (c *RedisCache) Delete(ctx context.Context, key string) {
	// UNLINK removes the key asynchroneously; so we are not blocking here.
	err := c.c.Unlink(ctx, key).Err()
	if err != nil {
		zerolog.Ctx(ctx).Info().Err(err).Msg("Failed to unlink value from cache")
	}
}

func (c *RedisCache) Check(ctx context.Context) error {
	if err := c.c.Ping(ctx).Err(); err != nil {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"failed connect to redis cache").CausedBy(err)
	}

	return nil
}
