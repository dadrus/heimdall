package propagators

import (
	"github.com/tonglil/opentelemetry-go-datadog-propagator"
	"go.opentelemetry.io/contrib/propagators/autoprop"
	"go.opentelemetry.io/otel/propagation"
)

//nolint:gochecknoinits
func init() {
	autoprop.RegisterTextMapPropagator("datadog", datadog.Propagator{})
}

func New() propagation.TextMapPropagator {
	return autoprop.NewTextMapPropagator()
}
