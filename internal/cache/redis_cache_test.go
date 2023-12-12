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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/dadrus/heimdall/internal/config"
)

func TestRedisCacheUsage(t *testing.T) {
	t.Parallel()

	redisCache := before(t)

	for _, tc := range []struct {
		uc             string
		key            string
		configureCache func(*testing.T, *RedisCache)
		assert         func(t *testing.T, data any)
	}{
		{
			uc:  "can retrieve not expired value",
			key: "foo",
			configureCache: func(t *testing.T, redis *RedisCache) {
				t.Helper()

				redis.Set(context.Background(), "foo", "bar", 10*time.Minute)
			},
			assert: func(t *testing.T, data any) {
				t.Helper()

				assert.Equal(t, "bar", data)
			},
		},
		{
			uc:  "cannot retrieve expired value",
			key: "bar",
			configureCache: func(t *testing.T, redis *RedisCache) {
				t.Helper()

				redis.Set(context.Background(), "bar", "baz", 1*time.Millisecond)

				time.Sleep(200 * time.Millisecond)
			},
			assert: func(t *testing.T, data any) {
				t.Helper()

				assert.Nil(t, data)
			},
		},
		{
			uc:  "cannot retrieve deleted value",
			key: "baz",
			configureCache: func(t *testing.T, redis *RedisCache) {
				t.Helper()

				redis.Set(context.Background(), "baz", "bar", 1*time.Second)
				redis.Delete(context.Background(), "baz")
			},
			assert: func(t *testing.T, data any) {
				t.Helper()

				assert.Nil(t, data)
			},
		},
		{
			uc:  "cannot retrieve not existing value",
			key: "baz",
			configureCache: func(t *testing.T, redis *RedisCache) {
				t.Helper()
			},
			assert: func(t *testing.T, data any) {
				t.Helper()

				assert.Nil(t, data)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			tc.configureCache(t, redisCache)

			data := redisCache.Get(context.Background(), tc.key)

			// THEN
			tc.assert(t, data)
		})
	}
}

func before(t *testing.T) *RedisCache {
	t.Helper()

	ctx := context.Background()
	redisC := initRedisContainer(ctx, t)

	endpoint, err := redisC.Endpoint(ctx, "")
	if err != nil {
		t.Error(err)
	}

	conf := &config.Configuration{
		Cache: config.CacheProviders{
			Type:   "redis",
			Config: map[string]any{"Addr": endpoint},
		},
	}

	cache, _ := NewRedisCache(conf)
	assert.NotEmpty(t, cache.c)

	t.Cleanup(func() {
		shutDownRedisContainer(ctx, t, redisC)
	})

	return cache
}

func initRedisContainer(ctx context.Context, t *testing.T) testcontainers.Container {
	t.Helper()

	req := testcontainers.ContainerRequest{
		Image:        "redis:latest",
		ExposedPorts: []string{"6379/tcp"},
		WaitingFor:   wait.ForLog("Ready to accept connections").WithStartupTimeout(30 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})

	failOnError(t, err, "Could not initialize postgres container")

	//	time.Sleep(4 * time.Second)
	return container
}

func shutDownRedisContainer(ctx context.Context, t *testing.T, c testcontainers.Container) {
	t.Helper()

	if err := c.Terminate(ctx); err != nil {
		t.Logf("could not terminate postgres container, reason: %s", err)
	}
}

func failOnError(t *testing.T, err error, msg string) {
	t.Helper()

	if err != nil {
		t.Fatalf(msg+", reason: %s", err)
	}
}
