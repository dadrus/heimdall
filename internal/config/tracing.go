package config

const (
	SpanProcessorSimple = "simple"
	SpanProcessorBatch  = "batch"
)

type TracingConfig struct {
	Enabled           bool   `koanf:"enabled"`
	SpanProcessorType string `koanf:"span_processor"`
}
