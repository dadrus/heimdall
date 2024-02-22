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

	"github.com/redis/rueidis"

	"github.com/dadrus/heimdall/internal/x/stringx"
)

type redisCache struct {
	c   rueidis.Client
	ttl time.Duration
}

func (c *redisCache) Start(_ context.Context) error {
	// not used for Redis.
	return nil
}

func (c *redisCache) Stop(_ context.Context) error {
	c.c.Close()

	return nil
}

func (c *redisCache) Get(ctx context.Context, key string) ([]byte, error) {
	val, err := c.c.DoCache(ctx, c.c.B().Get().Key(key).Cache(), c.ttl).ToString()
	if err != nil {
		return nil, err
	}

	return stringx.ToBytes(val), nil
}

func (c *redisCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return c.c.Do(ctx, c.c.B().Set().Key(key).Value(stringx.ToString(value)).Px(ttl).Build()).Error()
}
