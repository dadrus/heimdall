package otel

import (
	"context"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/opentelemetry/exporters"
	"github.com/dadrus/heimdall/internal/x/opentelemetry/propagators"
)

func initTraceProvider(
	conf *config.Configuration,
	res *resource.Resource,
	logger zerolog.Logger,
	lifecycle fx.Lifecycle,
) error {
	if !conf.Tracing.Enabled {
		logger.Info().Msg("OpenTelemetry tracing disabled.")

		return nil
	}

	spanExporters, err := exporters.NewSpanExporters(context.Background())
	if err != nil {
		return err
	}

	spanProcessorOption := x.IfThenElse(conf.Tracing.SpanProcessorType == config.SpanProcessorSimple,
		trace.WithSyncer,
		func(exporter trace.SpanExporter) trace.TracerProviderOption { return trace.WithBatcher(exporter) })

	tpOpts := []trace.TracerProviderOption{trace.WithResource(res)}
	for _, exporter := range spanExporters {
		tpOpts = append(tpOpts, spanProcessorOption(exporter))
	}

	tp := trace.NewTracerProvider(tpOpts...)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagators.New())

	lifecycle.Append(fx.StopHook(tp.Shutdown))

	logger.Info().Msg("OpenTelemetry tracing initialized.")

	return nil
}
