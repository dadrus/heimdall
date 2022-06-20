package config

type MetricsConfig struct {
	Prometheus PrometheusConfig `koanf:"prometheus"`
}
