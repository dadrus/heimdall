package propagators

import (
	"testing"

	"github.com/stretchr/testify/assert"
	datadog "github.com/tonglil/opentelemetry-go-datadog-propagator"
	"go.opentelemetry.io/otel/propagation"
)

func TestAvailablePropagators(t *testing.T) {
	for _, tc := range []struct {
		uc     string
		setup  func(t *testing.T)
		assert func(t *testing.T, propagator propagation.TextMapPropagator)
	}{
		{
			uc: "datadog propagator can be used",
			setup: func(t *testing.T) {
				t.Helper()

				t.Setenv("OTEL_PROPAGATORS", "datadog")
			},
			assert: func(t *testing.T, propagator propagation.TextMapPropagator) {
				t.Helper()

				assert.IsType(t, datadog.Propagator{}, propagator)
			},
		},
		{
			uc: "all available propagators can be used",
			setup: func(t *testing.T) {
				t.Helper()

				t.Setenv("OTEL_PROPAGATORS", "tracecontext,baggage,b3,b3multi,jaeger,xray,ottrace,datadog")
			},
			assert: func(t *testing.T, propagator propagation.TextMapPropagator) {
				t.Helper()

				assert.Len(t, propagator, 8)
				assert.Contains(t, propagator, datadog.Propagator{})
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {

		})
	}
}
