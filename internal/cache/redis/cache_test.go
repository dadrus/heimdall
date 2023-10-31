package redis

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	redisImage string = "redis:latest"
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
		}} {
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
	ctx := context.Background()
	redisC := initRedisContainer(ctx, t)

	endpoint, err := redisC.Endpoint(ctx, "")

	if err != nil {
		t.Error(err)
	}

	cache := NewRedisCache("redis://" + endpoint)
	assert.NotEmpty(t, cache.c)

	t.Cleanup(func() {
		shutDownRedisContainer(ctx, t, redisC)
	})
	return cache
}

func initRedisContainer(ctx context.Context, t *testing.T) testcontainers.Container {

	req := testcontainers.ContainerRequest{
		Image:        redisImage,
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
	if err := c.Terminate(ctx); err != nil {
		t.Logf("could not terminate postgres container, reason: %s", err)
	}
}

func failOnError(t *testing.T, err error, msg string) {
	if err != nil {
		t.Fatalf(msg+", reason: %s", err)
	}
}
