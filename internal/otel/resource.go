package otel

import (
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.18.0"

	"github.com/dadrus/heimdall/version"
)

func createResource() (*resource.Resource, error) {
	return resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			"",
			semconv.ServiceName("heimdall"),
			semconv.ServiceVersion(version.Version)))
}
