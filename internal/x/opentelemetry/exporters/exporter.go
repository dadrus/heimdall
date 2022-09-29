package exporters

import (
	"context"
	"os"
	"strings"

	"go.opentelemetry.io/otel/sdk/trace"
)

// otelTracesExportersEnvKey is the environment variable name identifying
// exporters to use.
const otelTracesExportersEnvKey = "OTEL_TRACES_EXPORTER"

// New returns a slice of trace.SpanExporters defined by the
// OTEL_TRACES_EXPORTER environment variable. An "otel" SpanExporter is returned
// if no exporter is defined for the environment variable. A no-op
// SpanExporter will be returned if "none" is defined anywhere in the
// environment variable.
func New(ctx context.Context) ([]trace.SpanExporter, error) {
	exporterNames, ok := os.LookupEnv(otelTracesExportersEnvKey)
	if !ok {
		return spanExporters(ctx)
	}

	return spanExporters(ctx, strings.Split(exporterNames, ",")...)
}
