package exporters

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
)

func TestNewWithoutSetEnvVariable(t *testing.T) {
	t.Parallel()

	// WHEN
	expts, err := New(context.Background())

	// THEN
	require.NoError(t, err)
	assert.Len(t, expts, 1)
	assert.IsType(t, expts[0], &otlptrace.Exporter{})
}

func TestNewWithSetEnvVariable(t *testing.T) {
	// GIVEN
	t.Setenv(otelTracesExportersEnvKey, "none")

	// WHEN
	expts, err := New(context.Background())

	// THEN
	require.NoError(t, err)
	assert.Len(t, expts, 1)
	assert.IsType(t, noopExporter{}, expts[0])
}
