package config

type TracingConfig struct {
	ServiceName string `koanf:"service_name"`
	Provider    string `koanf:"provider"`
}
