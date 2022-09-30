package config

type TracingConfig struct {
	Enabled   bool   `koanf:"enabled"`
	Processor string `koanf:"processor"`
}
