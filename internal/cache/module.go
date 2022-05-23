package cache

import (
	"context"

	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/cache/memory"
	"github.com/dadrus/heimdall/internal/config"
)

// nolint
var Module = fx.Options(
	fx.Provide(newCache),
	fx.Invoke(registerCacheEviction),
)

func newCache(conf config.Configuration, logger zerolog.Logger) Cache {
	if len(conf.Cache.Type) == 0 {
		logger.Info().Msg("Instantiating in memory cache")

		return memory.New()
	}

	return noopCache{}
}

func registerCacheEviction(lifecycle fx.Lifecycle, logger zerolog.Logger, cache Cache) {
	evictor, ok := cache.(Evictor)

	if !ok {
		return
	}

	lifecycle.Append(
		fx.Hook{
			OnStart: func(ctx context.Context) error {
				logger.Info().Msg("Starting cache evictor")
				go evictor.Start()

				return nil
			},
			OnStop: func(ctx context.Context) error {
				logger.Info().Msg("Tearing down cache evictor")
				evictor.Stop()

				return nil
			},
		},
	)
}
