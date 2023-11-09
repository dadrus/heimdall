package exporters

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/sdk/metric"

	"github.com/dadrus/heimdall/internal/x"
)

func TestCreateMetricReaders(t *testing.T) {
	for _, tc := range []struct {
		uc     string
		names  []string
		setup  func(t *testing.T)
		assert func(t *testing.T, err error, readers []metric.Reader)
	}{
		{
			uc:    "none exporter is at the beginning of the list",
			names: []string{"none", "foobar"},
			assert: func(t *testing.T, err error, readers []metric.Reader) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, readers, 1)
				assert.IsType(t, &metric.PeriodicReader{}, readers[0])
			},
		},
		{
			uc:    "none exporter is not at the beginning of the list",
			names: []string{"otlp", "none", "prometheus"},
			assert: func(t *testing.T, err error, readers []metric.Reader) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, readers, 1)
				assert.IsType(t, &metric.PeriodicReader{}, readers[0])
			},
		},
		{
			uc:    "list contains unsupported exporter type",
			names: []string{"otlp", "foobar"},
			assert: func(t *testing.T, err error, readers []metric.Reader) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrUnsupportedMetricExporterType)
				assert.Contains(t, err.Error(), "foobar")
			},
		},
		{
			uc:    "fails creating exporter type",
			names: []string{"otlp"},
			setup: func(t *testing.T) {
				t.Helper()

				t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "foobar")
			},
			assert: func(t *testing.T, err error, readers []metric.Reader) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrFailedCreatingMetricExporter)
				assert.Contains(t, err.Error(), "otlp")
				require.ErrorIs(t, err, ErrUnsupportedOTLPProtocol)
				assert.Contains(t, err.Error(), "foobar")
			},
		},
		{
			uc: "default exporter type with error",
			setup: func(t *testing.T) {
				t.Helper()
				t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "foobar")
			},
			assert: func(t *testing.T, err error, readers []metric.Reader) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrUnsupportedOTLPProtocol)
				assert.Contains(t, err.Error(), "foobar")
			},
		},
		{
			uc: "default exporter type",
			assert: func(t *testing.T, err error, readers []metric.Reader) {
				t.Helper()

				require.NoError(t, err)
				assert.Len(t, readers, 1)
				assert.IsType(t, &metric.PeriodicReader{}, readers[0])
			},
		},
		{
			uc:    "all supported exporter types",
			names: []string{"otlp", "prometheus"},
			setup: func(t *testing.T) {
				t.Helper()

				t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")
			},
			assert: func(t *testing.T, err error, readers []metric.Reader) {
				t.Helper()

				require.NoError(t, err)
				assert.Len(t, readers, 2)
				assert.IsType(t, &metric.PeriodicReader{}, readers[0])
				assert.IsType(t, &prometheus.Exporter{}, readers[1])
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			setup := x.IfThenElse(tc.setup == nil, func(t *testing.T) { t.Helper() }, tc.setup)
			setup(t)

			// WHEN
			readers, err := createMetricsReaders(context.Background(), tc.names...)

			// THEN
			tc.assert(t, err, readers)
		})
	}
}
