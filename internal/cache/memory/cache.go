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

package memory

import (
	"context"
	"errors"
	"github.com/dadrus/heimdall/internal/x"
	"time"

	"github.com/inhies/go-bytesize"
	"github.com/jellydator/ttlcache/v3"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/cache"
)

const defaultCacheMemorySize = 128 * bytesize.MB

var ErrNoCacheEntry = errors.New("no cache entry")

// by intention. Used only during application bootstrap.
func init() { // nolint: gochecknoinits
	cache.Register("in-memory", cache.FactoryFunc(NewCache))
}

func NewCache(_ app.Context, conf map[string]any) (cache.Cache, error) {
	type Config struct {
		MaxEntries uint64             `mapstructure:"max_entries"`
		MaxMemory  *bytesize.ByteSize `mapstructure:"max_memory"`
	}

	var cfg Config

	if len(conf) != 0 {
		err := decodeConfig(conf, &cfg)
		if err != nil {
			return nil, err
		}
	}

	maxMemory := x.IfThenElseExec(cfg.MaxMemory == nil,
		func() uint64 { return uint64(defaultCacheMemorySize) },
		func() uint64 { return uint64(*cfg.MaxMemory) },
	)

	return &Cache{
		c: ttlcache.New[string, []byte](
			ttlcache.WithDisableTouchOnHit[string, []byte](),
			ttlcache.WithCapacity[string, []byte](cfg.MaxEntries),
			ttlcache.WithMaxCost[string, []byte](maxMemory,
				func(item *ttlcache.Item[string, []byte]) uint64 {
					// An empty cache takes up 374 bytes.
					// Each entry incurs overhead: 16 bytes for the string (key) metadata and 24 bytes
					// for the []byte (value) metadata. The cache also maintains internal structures,
					// averaging about 144 bytes per entry. Combined, this results in an overhead of
					// approximately 184 bytes, excluding the empty cache size.
					const ttlCacheOverheadPerEntry = 184

					return uint64(len(item.Key()) + len(item.Value()) + ttlCacheOverheadPerEntry) //nolint:gosec
				},
			),
		),
	}, nil
}

type Cache struct {
	c *ttlcache.Cache[string, []byte]
}

func (c *Cache) Start(_ context.Context) error {
	go c.c.Start()

	return nil
}

func (c *Cache) Stop(_ context.Context) error {
	c.c.Stop()

	return nil
}

func (c *Cache) Get(_ context.Context, key string) ([]byte, error) {
	item := c.c.Get(key)
	if item == nil || item.IsExpired() {
		return nil, ErrNoCacheEntry
	}

	return item.Value(), nil
}

func (c *Cache) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	c.c.Set(key, value, ttl)

	return nil
}
