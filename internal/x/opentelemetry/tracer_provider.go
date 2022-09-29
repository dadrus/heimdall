package opentelemetry

import (
	"context"

	"github.com/dadrus/heimdall/internal/x/opentelemetry/exporters"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.12.0"
)

func NewTracerProvider(serviceName, serviceVersion string) (*trace.TracerProvider, error) {
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(serviceName),
			semconv.ServiceVersionKey.String(serviceVersion)),
	)
	if err != nil {
		return nil, err
	}

	opts := []trace.TracerProviderOption{trace.WithResource(res)}

	exporters, err := exporters.New(context.Background())
	if err != nil {
		return nil, err
	}

	for _, exporter := range exporters {
		opts = append(opts, trace.WithBatcher(exporter))
	}

	return trace.NewTracerProvider(opts...), nil
}
