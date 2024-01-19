// Copyright 2024 Dimitrij Drus <dadrus@gmx.de>
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
	cache.Register("redis-cluster", &clusterCacheFactory{})
}

type clusterCacheFactory struct{}

func (*clusterCacheFactory) Create(conf map[string]any) (cache.Cache, error) {
	return NewClusterCache(conf)
}

//nolint:revive
type ClusterCache struct {
	c *redis.ClusterClient
}

// Redis Cluster implementation of the Cache interface.
func NewClusterCache(conf map[string]any) (*ClusterCache, error) {
	type Config struct {
		Addrs          []string    `mapstructure:"addrs"            validate:"required,gt=0"`
		Username       string      `mapstructure:"username"`
		Password       string      `mapstructure:"password"`
		TLS            *config.TLS `mapstructure:"tls"`
		AdditionalCa   string      `mapstructure:"additional_ca"`
		ReadOnly       bool        `mapstructure:"read_only"`
		RouteByLatency bool        `mapstructure:"route_by_latency"`
		RouteRandomly  bool        `mapstructure:"route_randomly"`
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

	opt := &redis.ClusterOptions{
		ClientName:     "heimdall-cluster-client",
		Addrs:          cfg.Addrs,
		Username:       cfg.Username, // use your Redis user. More info https://redis.io/docs/management/security/acl/
		Password:       cfg.Password,
		ReadOnly:       cfg.ReadOnly,
		RouteByLatency: cfg.RouteByLatency,
		RouteRandomly:  cfg.RouteRandomly,
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

	client := redis.NewClusterClient(opt)

	_ = redisotel.InstrumentTracing(client)
	_ = redisotel.InstrumentMetrics(client)

	if err := client.Ping(context.Background()).Err(); err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"failed connect to redis cluster cache").CausedBy(err)
	}

	return &ClusterCache{c: client}, nil
}

func (c *ClusterCache) Start(_ context.Context) error {
	// not used for Redis.
	return nil
}

func (c *ClusterCache) Stop(_ context.Context) error {
	// not used for Redis.
	return nil
}

func (c *ClusterCache) Get(ctx context.Context, key string) any {
	val, err := c.c.Get(ctx, key).Result()
	if err != nil {
		zerolog.Ctx(ctx).Info().Err(err).Msg("Failed to fetch value from cache")

		return nil
	}

	return val
}

func (c *ClusterCache) Set(ctx context.Context, key string, value any, ttl time.Duration) {
	err := c.c.Set(ctx, key, value, ttl).Err()
	if err != nil {
		zerolog.Ctx(ctx).Info().Err(err).Msg("Failed to store value in cache")
	}
}

// remove a key.
func (c *ClusterCache) Delete(ctx context.Context, key string) {
	// UNLINK removes the key asynchroneously; so we are not blocking here.
	err := c.c.Unlink(ctx, key).Err()
	if err != nil {
		zerolog.Ctx(ctx).Info().Err(err).Msg("Failed to unlink value from cache")
	}
}
