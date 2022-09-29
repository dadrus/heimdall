package exporters

import (
	"context"

	"go.opentelemetry.io/otel/sdk/trace"
)

// NoopExporter is an exporter that drops all received spans and performs no
// action.
type noopExporter struct{}

// ExportSpans handles export of spans by dropping them.
func (noopExporter) ExportSpans(context.Context, []trace.ReadOnlySpan) error { return nil }

// Shutdown stops the exporter by doing nothing.
func (noopExporter) Shutdown(context.Context) error { return nil }
