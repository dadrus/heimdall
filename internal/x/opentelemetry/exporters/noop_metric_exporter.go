package exporters

import (
	"context"

	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

type noopMetricExporter struct{}

func (noopMetricExporter) Temporality(metric.InstrumentKind) metricdata.Temporality {
	return metricdata.DeltaTemporality
}

func (noopMetricExporter) Aggregation(metric.InstrumentKind) metric.Aggregation {
	return metric.AggregationDrop{}
}
func (noopMetricExporter) Export(context.Context, *metricdata.ResourceMetrics) error { return nil }
func (noopMetricExporter) ForceFlush(context.Context) error                          { return nil }
func (noopMetricExporter) Shutdown(context.Context) error                            { return nil }
