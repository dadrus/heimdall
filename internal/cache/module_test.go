package cache

import (
	"context"
	"testing"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/cache/memory"
	"github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/x"
)

func TestNewCache(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		conf   *config.Configuration
		assert func(t *testing.T, cch Cache)
	}{
		{
			uc:   "in memory cache",
			conf: &config.Configuration{},
			assert: func(t *testing.T, cch Cache) {
				t.Helper()

				assert.IsType(t, &memory.InMemoryCache{}, cch)
			},
		},
		{
			uc:   "disabled cache",
			conf: &config.Configuration{Cache: config.CacheConfig{Type: "foo"}},
			assert: func(t *testing.T, cch Cache) {
				t.Helper()

				assert.IsType(t, noopCache{}, cch)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			cch := newCache(tc.conf, log.Logger)

			// THEN
			tc.assert(t, cch)
		})
	}
}

type mockLifecycle struct{ mock.Mock }

func (m *mockLifecycle) Append(hook fx.Hook) { m.Called(hook) }

func TestCacheEvictorRegistration(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc             string
		cch            Cache
		configureMocks func(t *testing.T, lfc *mockLifecycle)
		assert         func(t *testing.T, cch Cache)
	}{
		{
			uc:  "cache does not implement required interface",
			cch: noopCache{},
			assert: func(t *testing.T, cch Cache) {
				// nothing to do here
				t.Helper()
			},
		},
		{
			uc: "cache implements evictor interface",
			cch: func() *mocks.MockCache {
				mcch := &mocks.MockCache{}

				mcch.On("Start")
				mcch.On("Stop")

				return mcch
			}(),
			configureMocks: func(t *testing.T, lfc *mockLifecycle) {
				t.Helper()

				lfc.On("Append", mock.MatchedBy(func(hook fx.Hook) bool {
					require.NoError(t, hook.OnStart(context.Background()))
					require.NoError(t, hook.OnStop(context.Background()))

					time.Sleep(100 * time.Millisecond)

					return true
				}))
			},
			assert: func(t *testing.T, cch Cache) {
				t.Helper()

				mcch, ok := cch.(*mocks.MockCache)
				require.True(t, ok)

				mcch.AssertExpectations(t)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			configureMocks := x.IfThenElse(tc.configureMocks != nil,
				tc.configureMocks,
				func(t *testing.T, lfc *mockLifecycle) { t.Helper() })

			lfc := &mockLifecycle{}
			configureMocks(t, lfc)

			// WHEN
			registerCacheEviction(lfc, log.Logger, tc.cch)

			// THEN
			tc.assert(t, tc.cch)
			lfc.AssertExpectations(t)
		})
	}
}
