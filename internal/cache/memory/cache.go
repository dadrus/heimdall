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
	"time"

	"github.com/jellydator/ttlcache/v3"
)

type InMemoryCache struct {
	c *ttlcache.Cache[string, any]
}

func New() *InMemoryCache {
	return &InMemoryCache{c: ttlcache.New[string, any](ttlcache.WithDisableTouchOnHit[string, any]())}
}

func (c *InMemoryCache) Start(_ context.Context) error {
	go c.c.Start()

	return nil
}

func (c *InMemoryCache) Stop(_ context.Context) error {
	c.c.Stop()

	return nil
}

func (c *InMemoryCache) Get(_ context.Context, key string) any {
	item := c.c.Get(key)
	if item != nil && !item.IsExpired() {
		return item.Value()
	}

	return nil
}

func (c *InMemoryCache) Set(_ context.Context, key string, value any, ttl time.Duration) {
	c.c.Set(key, value, ttl)
}

func (c *InMemoryCache) Delete(_ context.Context, key string) { c.c.Delete(key) }
