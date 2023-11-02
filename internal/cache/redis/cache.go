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
	"crypto/tls"
	"crypto/x509"
	"log"
	"os"
	"time"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/keystore"
	redis "github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
)

type RedisCache struct {
	c *redis.Client
}

func NewRedisCache(cfg *config.CacheConfig, logger zerolog.Logger) *RedisCache {

	opt := &redis.Options{
		Addr:     cfg.RedisConfig.Addr,
		Username: cfg.RedisConfig.Username, // use your Redis user. More info https://redis.io/docs/management/security/acl/
		Password: cfg.RedisConfig.Password,
		DB:       cfg.RedisConfig.DB,
	}

	if cfg.RedisConfig.TLS != nil && len(cfg.RedisConfig.TLS.KeyStore.Path) != 0 {
		tlsConfig, err := configureTLS(cfg, logger)

		if err == nil {
			logger.Info().Msg("TLS for Redis connection enabled")
			opt.TLSConfig = tlsConfig
		} else {
			logger.Info().Err(err).Msg("TLS for Redis connection failed")
		}
	} else {
		logger.Info().Msg("TLS for Redis connection disabled. NEVER DO IT IN PRODUCTION!!!!")
	}

	client := redis.NewClient(opt)
	return &RedisCache{c: client}
}

func configureTLS(cfg *config.CacheConfig, logger zerolog.Logger) (*tls.Config, error) {
	var (
		ks  keystore.KeyStore
		kse *keystore.Entry
		err error
	)

	ks, err = keystore.NewKeyStoreFromPEMFile(cfg.RedisConfig.TLS.KeyStore.Path, cfg.RedisConfig.TLS.KeyStore.Password)

	if err != nil {
		logger.Info().Err(err).Msg("Failed to load keystore ")
		return nil, err
	}

	if len(cfg.RedisConfig.TLS.KeyID) != 0 {
		if kse, err = ks.GetKey(cfg.RedisConfig.TLS.KeyID); err != nil {
			logger.Info().Err(err).Msg("Failed to fetch value from cache ")
			return nil, err
		}
	} else {
		kse = ks.Entries()[0]
	}

	cert, err := keystore.ToTLSCertificate(kse)
	if err != nil {
		return nil, err
	}

	caCert, err := os.ReadFile(cfg.RedisConfig.AdditionalCA)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tls := &tls.Config{
		MinVersion:   cfg.RedisConfig.TLS.MinVersion.OrDefault(),
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}
	return tls, nil

}

func (c *RedisCache) Start(_ context.Context) error {
	return nil
}

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
	_ = c.c.Set(ctx, key, value, ttl).Err()
}

func (c *RedisCache) Delete(ctx context.Context, key string) {
	c.c.Unlink(ctx, key).Result()
}
