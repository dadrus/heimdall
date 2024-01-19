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

package redis

import (
	"context"
	"time"

	"github.com/redis/go-redis/extra/redisotel/v9"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap.
func init() { // nolint: gochecknoinits
	cache.Register("redis", &simpleCacheFactory{})
}

type simpleCacheFactory struct{}

func (*simpleCacheFactory) Create(conf map[string]any) (cache.Cache, error) {
	return NewSimpleCache(conf)
}

type SimpleCache struct {
	c *redis.Client
}

func NewSimpleCache(conf map[string]any) (*SimpleCache, error) {
	type Config struct {
		Addr         string      `mapstructure:"addr"          validate:"required"`
		Username     string      `mapstructure:"username"`
		Password     string      `mapstructure:"password"`
		DB           int         `mapstructure:"db"`
		TLS          *config.TLS `mapstructure:"tls"`
		AdditionalCa string      `mapstructure:"additional_ca"`
	}

	var cfg Config

	if err := decodeConfig(conf, &cfg); err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"failed decoding redis cache config").CausedBy(err)
	}

	if err := validation.ValidateStruct(&cfg); err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"failed validating redis cache config").CausedBy(err)
	}

	opt := &redis.Options{
		ClientName: "heimdall",
		Addr:       cfg.Addr,
		Username:   cfg.Username, // use your Redis user. More info https://redis.io/docs/management/security/acl/
		Password:   cfg.Password,
		DB:         cfg.DB,
	}

	if cfg.TLS != nil && len(cfg.TLS.KeyStore.Path) != 0 {
		tlsConfig, err := configureTLS(cfg.TLS, cfg.AdditionalCa)

		if err == nil {
			opt.TLSConfig = tlsConfig
		} else {
			return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
				"failed configuring tls for redis cache").CausedBy(err)
		}
	}

	client := redis.NewClient(opt)

	_ = redisotel.InstrumentTracing(client)
	_ = redisotel.InstrumentMetrics(client)

	if err := client.Ping(context.Background()).Err(); err != nil {
		return nil, errorchain.NewWithMessage(ErrConnectionCheckFailed, "failed connect to redis cache").
			CausedBy(err)
	}

	return &SimpleCache{c: client}, nil
}

func (c *SimpleCache) Start(_ context.Context) error {
	// not used for Redis.
	return nil
}

func (c *SimpleCache) Stop(_ context.Context) error {
	// not used for Redis.
	return nil
}

func (c *SimpleCache) Get(ctx context.Context, key string) any {
	val, err := c.c.Get(ctx, key).Result()
	if err != nil {
		zerolog.Ctx(ctx).Info().Err(err).Msg("Failed to fetch value from cache")

		return nil
	}

	return val
}

func (c *SimpleCache) Set(ctx context.Context, key string, value any, ttl time.Duration) {
	err := c.c.Set(ctx, key, value, ttl).Err()
	if err != nil {
		zerolog.Ctx(ctx).Info().Err(err).Msg("Failed to store value in cache")
	}
}

func (c *SimpleCache) Delete(ctx context.Context, key string) {
	// UNLINK removes the key asynchronously; so we are not blocking here.
	err := c.c.Unlink(ctx, key).Err()
	if err != nil {
		zerolog.Ctx(ctx).Info().Err(err).Msg("Failed to unlink value from cache")
	}
}
