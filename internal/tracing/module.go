package tracing

import (
	"context"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.12.0"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/opentelemetry/exporters"
	"github.com/dadrus/heimdall/internal/x/opentelemetry/propagators"
	"github.com/dadrus/heimdall/version"
)

// Module is used on app bootstrap.
// nolint: gochecknoglobals
var Module = fx.Options(
	fx.Invoke(initializeOTEL),
)

func initializeOTEL(lifecycle fx.Lifecycle, conf config.Configuration, logger zerolog.Logger) error {
	if !conf.Tracing.Enabled {
		logger.Info().Msg("Opentelemetry tracing disabled.")

		return nil
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String("heimdall"),
			semconv.ServiceVersionKey.String(version.Version)))
	if err != nil {
		return err
	}

	xprts, err := exporters.New(context.Background())
	if err != nil {
		return err
	}

	processorOption := x.IfThenElse(conf.Tracing.Processor == "simple",
		trace.WithSyncer,
		func(exporter trace.SpanExporter) trace.TracerProviderOption { return trace.WithBatcher(exporter) })

	opts := []trace.TracerProviderOption{trace.WithResource(res)}
	for _, exporter := range xprts {
		opts = append(opts, processorOption(exporter))
	}

	provider := trace.NewTracerProvider(opts...)

	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagators.New())
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) { logger.Error().Err(err).Msg("OTEL Error") }))

	lifecycle.Append(fx.Hook{OnStop: func(ctx context.Context) error {
		logger.Info().Msg("Tearing down Opentelemetry provider")

		return provider.Shutdown(ctx)
	}})

	logger.Info().Msg("Opentelemetry tracing initialized.")

	return nil
}
