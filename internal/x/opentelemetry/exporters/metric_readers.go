package exporters

import (
	"context"
	"os"
	"strings"

	"go.opentelemetry.io/otel/sdk/metric"
)

// NewMetricReaders returns a slice of metric.Reader defined by the
// OTEL_METRICS_EXPORTER environment variable. An "otel" Exporter is returned
// if no exporter is defined for the environment variable. A no-op
// Exporter will be returned if "none" is defined anywhere in the
// environment variable.
func NewMetricReaders(ctx context.Context) ([]metric.Reader, error) {
	exporterNames, ok := os.LookupEnv("OTEL_METRICS_EXPORTER")
	if !ok {
		return createMetricsReaders(ctx)
	}

	return createMetricsReaders(ctx, strings.Split(exporterNames, ",")...)
}
