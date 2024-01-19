package config

type CacheConfig struct {
	Type   string         `koanf:"type"`
	Config map[string]any `koanf:"config"`
}
