package cache

import (
	"context"

	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/cache/memory"
)

// nolint
var Module = fx.Options(
	fx.Provide(memory.New),
	fx.Invoke(registerCacheEviction),
)

func registerCacheEviction(lifecycle fx.Lifecycle, logger zerolog.Logger, cache Cache) {
	lifecycle.Append(
		fx.Hook{
			OnStart: func(ctx context.Context) error {
				logger.Info().Msg("Starting cache evictor")
				go cache.Start()

				return nil
			},
			OnStop: func(ctx context.Context) error {
				logger.Info().Msg("Tearing down cache evictor")
				cache.Stop()

				return nil
			},
		},
	)
}
