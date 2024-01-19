package config

type CacheProviders struct {
	Type   string         `koanf:"type"`
	Config map[string]any `koanf:"config"`
}
