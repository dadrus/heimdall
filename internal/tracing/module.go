package tracing

import (
	"context"

	"github.com/dadrus/heimdall/internal/x/tracing"
	"github.com/opentracing/opentracing-go"
	"github.com/rs/zerolog"
	"go.uber.org/fx"
)

var Module = fx.Options(
	fx.Invoke(registerTracer),
)

func registerTracer(lifecycle fx.Lifecycle, logger zerolog.Logger) {
	tracer, closer, err := tracing.New("Heimdall")
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
