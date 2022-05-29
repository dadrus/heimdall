package tracing

import (
	"context"

	"github.com/opentracing/opentracing-go"
	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/x/tracing/provider"
)

// Module is used on app bootstrap.
// nolint: gochecknoglobals
var Module = fx.Options(
	fx.Invoke(registerTracer),
)

func registerTracer(lifecycle fx.Lifecycle, conf config.Configuration, logger zerolog.Logger) {
	if len(conf.Tracing.Provider) == 0 {
		logger.Info().Msg("No opentracing provider configured. Tracing will be disabled.")

		return
	}

	tracer, closer, err := provider.New(conf.Tracing.Provider, conf.Tracing.ServiceName, logger)
	if err != nil {
		logger.Warn().Err(err).Msg("Could not initialize opentracing tracer. Tracing will be disabled.")

		return
	}

	opentracing.InitGlobalTracer(tracer)

	logger.Info().Msg("Opentracing tracer initialized.")

	lifecycle.Append(
		fx.Hook{
			OnStop: func(ctx context.Context) error {
				closer.Close()

				return nil
			},
		},
	)
}
