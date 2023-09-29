package otel

import (
	"context"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/x/opentelemetry/exporters"
)

func initMeterProvider(
	conf *config.Configuration,
	res *resource.Resource,
	logger zerolog.Logger,
	lifecycle fx.Lifecycle,
) error {
	if !conf.Metrics.Enabled {
		logger.Info().Msg("OpenTelemetry metrics disabled.")

		return nil
	}

	metricsReaders, err := exporters.NewMetricReaders(context.Background())
	if err != nil {
		return err
	}

	opts := make([]metric.Option, len(metricsReaders)+1)
	opts[0] = metric.WithResource(res)

	for i, reader := range metricsReaders {
		opts[i+1] = metric.WithReader(reader)
	}

	mp := metric.NewMeterProvider(opts...)
	otel.SetMeterProvider(mp)
	lifecycle.Append(fx.StopHook(mp.Shutdown))

	logger.Info().Msg("OpenTelemetry metrics initialized.")

	return nil
}
