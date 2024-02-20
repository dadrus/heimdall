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
	"errors"
	"time"

	"github.com/inhies/go-bytesize"
	"github.com/redis/rueidis"
	"github.com/redis/rueidis/rueidisotel"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

var ErrConnectionCheckFailed = errors.New("cache connection failed")

type Cache struct {
	c   rueidis.Client
	ttl time.Duration
}

func NewCache(conf map[string]any) (*Cache, error) {
	type (
		ClientCache struct {
			Disabled          bool              `mapstructure:"disabled"`
			TTL               time.Duration     `mapstructure:"ttl"`
			SizePerConnection bytesize.ByteSize `mapstructure:"size_per_connection"`
		}

		Config struct {
			Addrs         []string           `mapstructure:"addrs"           validate:"gt=0,dive,required"`
			Username      string             `mapstructure:"username"`
			Password      string             `mapstructure:"password"`
			DB            int                `mapstructure:"db"`
			ClientCache   ClientCache        `mapstructure:"client_cache"`
			BufferLimit   config.BufferLimit `mapstructure:"buffer_limit"`
			Timeout       config.Timeout     `mapstructure:"timeout"`
			MaxFlushDelay time.Duration      `mapstructure:"max_flush_delay"`
		}
	)

	cfg := Config{ClientCache: ClientCache{TTL: 5 * time.Minute}} //nolint:gomnd

	err := decodeConfig(conf, &cfg)
	if err != nil {
		return nil, err
	}

	opts := rueidis.ClientOption{
		ClientName:          "heimdall",
		InitAddress:         cfg.Addrs,
		ShuffleInit:         true,
		SelectDB:            cfg.DB,
		Username:            cfg.Username,
		Password:            cfg.Password,
		DisableCache:        cfg.ClientCache.Disabled,
		CacheSizeEachConn:   int(cfg.ClientCache.SizePerConnection),
		WriteBufferEachConn: int(cfg.BufferLimit.Write),
		ReadBufferEachConn:  int(cfg.BufferLimit.Read),
		ConnWriteTimeout:    cfg.Timeout.Write,
		MaxFlushDelay:       cfg.MaxFlushDelay,
	}

	client, err := rueidisotel.NewClient(opts)
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed creating redis client").CausedBy(err)
	}

	return &Cache{c: client, ttl: cfg.ClientCache.TTL}, nil
}

func (c *Cache) Start(_ context.Context) error {
	// not used for Redis.
	return nil
}

func (c *Cache) Stop(_ context.Context) error {
	c.c.Close()

	return nil
}

func (c *Cache) Get(ctx context.Context, key string) ([]byte, error) {
	val, err := c.c.DoCache(ctx, c.c.B().Get().Key(key).Cache(), c.ttl).ToString()
	if err != nil {
		return nil, err
	}

	return stringx.ToBytes(val), nil
}

func (c *Cache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return c.c.Do(ctx, c.c.B().Set().Key(key).Value(stringx.ToString(value)).Px(ttl).Build()).Error()
}
