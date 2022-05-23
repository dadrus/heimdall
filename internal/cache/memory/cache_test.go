package memory

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCacheUsage(t *testing.T) {
	t.Parallel()

	cache := New()

	for _, tc := range []struct {
		uc             string
		key            string
		configureCache func(t *testing.T, cache *InMemoryCache)
		assert         func(t *testing.T, data any)
	}{
		{
			uc:  "can retrieve not expired value",
			key: "foo",
			configureCache: func(t *testing.T, cache *InMemoryCache) {
				t.Helper()

				cache.Set("foo", "bar", 10*time.Minute)
			},
			assert: func(t *testing.T, data any) {
				t.Helper()

				assert.Equal(t, "bar", data)
			},
		},
		{
			uc:  "cannot retrieve expired value",
			key: "bar",
			configureCache: func(t *testing.T, cache *InMemoryCache) {
				t.Helper()

				cache.Set("bar", "baz", 1*time.Microsecond)

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
			configureCache: func(t *testing.T, cache *InMemoryCache) {
				t.Helper()

				cache.Set("baz", "bar", 1*time.Second)
				cache.Delete("baz")
			},
			assert: func(t *testing.T, data any) {
				t.Helper()

				assert.Nil(t, data)
			},
		},
		{
			uc:  "cannot retrieve not existing value",
			key: "baz",
			configureCache: func(t *testing.T, cache *InMemoryCache) {
				t.Helper()
			},
			assert: func(t *testing.T, data any) {
				t.Helper()

				assert.Nil(t, data)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// SETUP
			cache.Delete(tc.key)

			// WHEN
			tc.configureCache(t, cache)

			data := cache.Get(tc.key)

			// THEN
			tc.assert(t, data)
		})
	}
}
