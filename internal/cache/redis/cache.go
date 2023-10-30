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

	redis "github.com/redis/go-redis/v9"
)

type RedisCache struct {
	c *redis.Client
}

func NewRedisCache(opt *redis.Options) *RedisCache {
	/*	opt, err := redis.ParseURL(dsn)
		if err != nil {
			panic(err)
		}
	*/
	client := redis.NewClient(opt)
	return &RedisCache{c: client}
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
